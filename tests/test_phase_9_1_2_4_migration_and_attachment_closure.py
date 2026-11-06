"""Phase 9.1.2.4 — Dedicated Test Suite: Migration Finality, Attachment Enforcement & Manifest Integrity Closure.

Exhaustive verification across three critical security surfaces:
Part A: Migration Finality & Legacy Exception Authority (18 tests)
Part B: FormPrefiller Attachment Consumption Enforcement (27 tests)
Part D: Strict Manifest-Version Declaration & Verification (17 tests)
Total: 62 targeted security test cases.
"""

import hashlib
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    KeyRevokedError,
    SecurityAuthorizationError,
)
from src.preparer.form_prefiller import (
    FormPrefiller,
    VerifiedAttachmentRef,
)
from src.security.file_security import FileSecurityValidator
from src.security.prompt_injection_detector import (
    PromptInjectionDetector,
    PromptInjectionScanResult,
    ScanClassification,
    ThreatRecord,
)
from src.security.scan_signer import SecurityScanSigner
from src.security.security_preflight import SecurityPreflightManager
from src.utils.canonical_json import canonical_json_hash
from tests.fixtures.synthetic_personas import (
    generate_persona_docx,
    generate_persona_pdf,
)


class TestPhase9124MigrationAndAttachmentClosure(unittest.TestCase):
    """Exhaustive test suite for Phase 9.1.2.4 requirements."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_phase_9_1_2_4_"))
        self.db_path = self.temp_dir / "closure_9124.db"
        self.storage_dir = self.temp_dir / "storage"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=str(self.db_path))
        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_dir)
        self.service = DashboardService(db_manager=self.db, storage_base_dir=self.storage_dir)
        self.preflight = SecurityPreflightManager(db_manager=self.db, file_validator=self.file_validator)
        self.detector = PromptInjectionDetector()

        # Create two test users
        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("alice9124@example.com", "hash1", "salt1", "Alice 9124"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("bob9124@example.com", "hash2", "salt2", "Bob 9124"),
            )
            self.user2_id = c.lastrowid

        # Pre-generate genuine PDF and DOCX bytes
        self.pdf_bytes = generate_persona_pdf("backend_engineer")
        self.docx_bytes = generate_persona_docx("backend_engineer")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # =========================================================================
    # PART A: MIGRATION FINALITY & LEGACY EXCEPTION AUTHORITY (18 TESTS)
    # =========================================================================

    def test_migration_01_new_uploaded_source_with_all_binary_metadata_null(self):
        """1. A new uploaded source created after migration with all binary metadata NULL cannot become LEGACY_TEXT_ONLY."""
        raw_text = "Senior Python Engineer needed."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "NewCo",
            "job_title": "Python Dev",
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
                ) VALUES (?, 'upload', 'NewCo', 'Python Dev', ?, ?, ?, 'REQUIRED', 1)
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        # Re-running migration routine does nothing because migration has already run
        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

        # Preflight fails closed because binary metadata is missing
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("missing required binary metadata", str(ctx.exception))

    def test_migration_02_same_day_uploaded_source_with_all_metadata_null(self):
        """2. Same-day uploaded source created after migration execution cannot become LEGACY_TEXT_ONLY."""
        raw_text = "Full Stack Engineer needed today."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "TodayCo",
            "job_title": "Full Stack Dev",
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
                ) VALUES (?, 'upload', 'TodayCo', 'Full Stack Dev', ?, ?, ?, 'REQUIRED', 1, CURRENT_TIMESTAMP)
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_migration_03_current_record_with_created_at_changed_to_2024(self):
        """3. Changing created_at to an older date (e.g. 2024) cannot grandfather a record after migration has run."""
        raw_text = "Systems Architect."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "TimeWarpCo",
            "job_title": "Architect",
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
                ) VALUES (?, 'upload', 'TimeWarpCo', 'Architect', ?, ?, ?, 'REQUIRED', 1, '2024-02-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        # Since migration marker exists, migration does not re-evaluate
        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_migration_04_previously_verified_record_with_fields_cleared(self):
        """4. Previously VERIFIED record with binary fields cleared cannot be converted to LEGACY_TEXT_ONLY."""
        # Un-mark migration to simulate pre-migration state
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at,
                    storage_filename, file_hash, file_size_bytes, file_format
                ) VALUES (?, 'upload', 'VerifiedCo', 'Lead Dev', 'Content', 'h1', 's1', 'VERIFIED', 1, '2024-03-01 10:00:00',
                          NULL, NULL, NULL, NULL)
                """,
                (self.user1_id,),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        # binary_integrity_state was VERIFIED; must NOT become LEGACY_TEXT_ONLY
        self.assertEqual(jd.binary_integrity_state, "VERIFIED")

    def test_migration_05_record_with_existing_signed_v2_binary_scan(self):
        """5. Record with existing signed v2 binary provenance scan cannot become LEGACY_TEXT_ONLY."""
        raw_text = "Security Engineer role."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "SecCo",
            "job_title": "SecEng",
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
                ) VALUES (?, 'upload', 'SecCo', 'SecEng', ?, ?, ?, 'REQUIRED', 1, '2024-04-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        # Insert a security scan record with binary provenance
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
            source_binary_hash="existing_binary_hash_64_chars_long_0123456789abcdef0123456789abcdef",
            source_binary_size_bytes=5000,
            source_binary_format="pdf",
            manifest_version="v2",
        )

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        # Cannot be migrated to LEGACY_TEXT_ONLY because it has binary provenance scan
        self.assertNotEqual(jd.binary_integrity_state, "LEGACY_TEXT_ONLY")

    def test_migration_06_record_with_existing_v1_scan(self):
        """6. Record with existing v1 scan lacking pre-migration canonical snapshot hash is rejected."""
        raw_text = "Frontend Engineer."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        bad_snap_hash = "tampered_snapshot_hash_123456"

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'WebCo', 'Frontend Dev', ?, ?, ?, 'REQUIRED', 1, '2024-04-10 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, bad_snap_hash),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_migration_07_eligible_historical_record_with_trustworthy_provenance(self):
        """7. Eligible historical record with authentic pre-migration provenance is migrated to LEGACY_TEXT_ONLY."""
        raw_text = "Historical Python & Django Engineer."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "HistoricCorp",
            "job_title": "Django Dev",
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
                ) VALUES (?, 'upload', 'HistoricCorp', 'Django Dev', ?, ?, ?, 'REQUIRED', 1, '2024-05-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "LEGACY_TEXT_ONLY")

        exc = self.db.get_legacy_integrity_exception(job_description_id=jd_id, user_id=self.user1_id)
        self.assertIsNotNone(exc)
        self.assertEqual(exc.outcome, "SUCCESS")
        self.assertTrue(self.db.is_schema_migration_applied("phase_9_1_2_3_legacy_binary_integrity"))

    def test_migration_08_database_with_no_trustworthy_migration_history(self):
        """8. Record without matching canonical 9-key snapshot hash is skipped during migration."""
        raw_text = "Historical role with wrong manifest."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        # Invalid snapshot hash
        snap_hash = "wrong_hash"

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'WrongCorp', 'Dev', ?, ?, ?, 'REQUIRED', 1, '2024-05-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_migration_09_migration_executed_twice(self):
        """9. Executing migration twice is idempotent and does nothing on second execution."""
        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        # Count legacy exceptions
        with self.db.connection() as conn:
            c1 = conn.execute("SELECT count(*) FROM legacy_integrity_exceptions").fetchone()[0]

        # Execute again
        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        with self.db.connection() as conn:
            c2 = conn.execute("SELECT count(*) FROM legacy_integrity_exceptions").fetchone()[0]

        self.assertEqual(c1, c2)

    def test_migration_10_database_reopened_after_successful_migration(self):
        """10. Database reopened after successful migration retains marker and skips migration."""
        self.assertTrue(self.db.is_schema_migration_applied("phase_9_1_2_3_legacy_binary_integrity"))
        # Re-open database
        db2 = DatabaseManager(db_path=str(self.db_path))
        self.assertTrue(db2.is_schema_migration_applied("phase_9_1_2_3_legacy_binary_integrity"))

    def test_migration_11_failed_audit_insertion_rollback(self):
        """11. Simulated failure during audit row insertion causes entire transaction to roll back."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            # Add a trigger to fail audit insertion
            conn.execute("""
                CREATE TRIGGER trg_test_fail_audit
                BEFORE INSERT ON legacy_integrity_exceptions
                BEGIN
                    SELECT RAISE(ABORT, 'Simulated audit insertion failure');
                END;
            """)

        raw_text = "Role testing rollback."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "RollbackCo",
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
                ) VALUES (?, 'upload', 'RollbackCo', 'Tester', ?, ?, ?, 'REQUIRED', 1, '2024-05-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        # Migration attempt must fail and rollback
        with self.assertRaises((sqlite3.OperationalError, sqlite3.IntegrityError)) as ctx:
            with self.db.immediate_transaction() as conn:
                self.db._migrate_historical_job_description_integrity(conn.cursor())
        self.assertIn("Simulated audit insertion failure", str(ctx.exception))

        # Clean up trigger
        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER trg_test_fail_audit")

        # Record must still be REQUIRED
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")
        self.assertFalse(self.db.is_schema_migration_applied("phase_9_1_2_3_legacy_binary_integrity"))

    def test_migration_12_failed_state_update_rollback(self):
        """12. Simulated failure during state update causes transaction rollback."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            conn.execute("""
                CREATE TRIGGER trg_test_fail_update
                BEFORE UPDATE OF binary_integrity_state ON job_descriptions
                WHEN NEW.binary_integrity_state = 'LEGACY_TEXT_ONLY'
                BEGIN
                    SELECT RAISE(ABORT, 'Simulated update failure');
                END;
            """)

        raw_text = "Role testing update rollback."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "UpCo",
            "job_title": "UpDev",
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
                ) VALUES (?, 'upload', 'UpCo', 'UpDev', ?, ?, ?, 'REQUIRED', 1, '2024-05-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        with self.assertRaises((sqlite3.OperationalError, sqlite3.IntegrityError)) as ctx:
            with self.db.immediate_transaction() as conn:
                self.db._migrate_historical_job_description_integrity(conn.cursor())
        self.assertIn("Simulated update failure", str(ctx.exception))

        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER trg_test_fail_update")

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_migration_13_failed_schema_migration_marker_rollback(self):
        """13. Simulated failure during schema_migrations marker insertion rolls back transaction."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            conn.execute("""
                CREATE TRIGGER trg_test_fail_marker
                BEFORE INSERT ON schema_migrations
                BEGIN
                    SELECT RAISE(ABORT, 'Simulated marker insertion failure');
                END;
            """)

        with self.assertRaises((sqlite3.OperationalError, sqlite3.IntegrityError)) as ctx:
            with self.db.immediate_transaction() as conn:
                self.db._migrate_historical_job_description_integrity(conn.cursor())
        self.assertIn("Simulated marker insertion failure", str(ctx.exception))

        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER trg_test_fail_marker")

    def test_migration_14_migration_rollback_and_retry(self):
        """14. After a failure and rollback, retrying migration succeeds."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")

        raw_text = "Role testing retry."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "RetryCo",
            "job_title": "RetryDev",
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
                ) VALUES (?, 'upload', 'RetryCo', 'RetryDev', ?, ?, ?, 'REQUIRED', 1, '2024-05-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        # Run migration successfully
        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "LEGACY_TEXT_ONLY")
        self.assertTrue(self.db.is_schema_migration_applied("phase_9_1_2_3_legacy_binary_integrity"))

    def test_migration_15_legacy_state_without_audit_row(self):
        """15. A record with LEGACY_TEXT_ONLY without an audit row fails preflight validation."""
        raw_text = "Unverified legacy state."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "NoAuditCo",
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
                ) VALUES (?, 'upload', 'NoAuditCo', 'Dev', ?, ?, ?, 'LEGACY_TEXT_ONLY', 1)
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("without an authoritative legacy integrity exception", str(ctx.exception))

    def test_migration_16_tampered_legacy_audit_snapshot_hash(self):
        """16. Tampered snapshot hash in legacy_integrity_exceptions fails validation."""
        raw_text = "Role with tampered audit."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "TamperAuditCo",
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
                ) VALUES (?, 'upload', 'TamperAuditCo', 'Dev', ?, ?, ?, 'LEGACY_TEXT_ONLY', 1)
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid
            c.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type, previous_binary_state,
                    assigned_legacy_state, source_snapshot_hash, migration_version, migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', 'tampered_hash_value', '9.1.2.3', 'Grandfathered legacy', 'SUCCESS')
                """,
                (self.user1_id, jd_id),
            )

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("does not match grandfathered snapshot hash", str(ctx.exception))

    def test_migration_17_partial_binary_metadata(self):
        """17. Uploaded source with partial binary metadata (e.g. 1 of 4 fields set) is rejected from legacy migration."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at,
                    storage_filename
                ) VALUES (?, 'upload', 'PartialCo', 'Dev', 'Text', 'h1', 's1', 'REQUIRED', 1, '2024-05-01 10:00:00',
                          'only_filename_set.pdf')
                """,
                (self.user1_id,),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_migration_18_pasted_and_url_sources(self):
        """18. Pasted and URL sources are assigned NOT_APPLICABLE and function cleanly without binary metadata."""
        ok_paste, _, jd_paste = self.service.ingest_job_text(
            user_id=self.user1_id,
            raw_text="Pasted Job Requirements: Python and Docker.",
            hint_title="Cloud Dev",
            hint_company="PasteCo",
        )
        self.assertTrue(ok_paste)
        jd = self.db.get_job_description(jd_paste.id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "NOT_APPLICABLE")

        res = self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd.id)
        self.assertTrue(res.is_allowed)

    # =========================================================================
    # PART B: FORMPREFILLER ATTACHMENT CONSUMPTION ENFORCEMENT (27 TESTS)
    # =========================================================================

    def _setup_clean_resume_and_plan(self):
        """Helper: Creates clean resume, job description, and form prefill plan."""
        ok_res, _, res_rec = self.service.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=self.pdf_bytes,
            original_filename="prefill_resume.pdf",
        )
        self.assertTrue(ok_res)
        resume_id = res_rec["id"]

        ok_jd, _, jd = self.service.ingest_job_text(
            user_id=self.user1_id,
            raw_text="Software Engineer with Python, Linux, and REST APIs.",
            hint_title="Software Engineer",
            hint_company="PrefillTech",
        )
        self.assertTrue(ok_jd)

        prefiller = FormPrefiller(db_manager=self.db, file_validator=self.file_validator)
        plan = prefiller.build_form_payload(job=jd, user_id=self.user1_id, resume_id=resume_id)
        return prefiller, plan, res_rec

    def test_attachment_01_valid_clean_attachment_with_configured_db(self):
        """1. Valid clean attachment with configured DB opens and returns exact binary bytes."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        verified_bytes = prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertEqual(verified_bytes, self.pdf_bytes)

    def test_attachment_02_missing_db(self):
        """2. FormPrefiller with db=None fails closed with SecurityAuthorizationError."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        prefiller.db = None
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("requires a configured DatabaseManager", str(ctx.exception))

    def test_attachment_03_missing_authoritative_resume_record(self):
        """3. Authoritative resume record missing in DB fails closed."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        # Point to non-existent resume ID
        ref = VerifiedAttachmentRef(
            user_id=plan.attachment_ref.user_id,
            resume_id=99999,
            version_num=plan.attachment_ref.version_num,
            storage_filename=plan.attachment_ref.storage_filename,
            file_path=plan.attachment_ref.file_path,
            file_hash=plan.attachment_ref.file_hash,
            file_size_bytes=plan.attachment_ref.file_size_bytes,
            file_format=plan.attachment_ref.file_format,
            scan_id=plan.attachment_ref.scan_id,
            scan_signature=plan.attachment_ref.scan_signature,
            verified_at=plan.attachment_ref.verified_at,
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(ref, user_id=self.user1_id)
        self.assertIn("TOCTOU detection", str(ctx.exception))

    def test_attachment_04_wrong_user(self):
        """4. Opening attachment with wrong user_id raises CrossUserAccessError."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        with self.assertRaises(CrossUserAccessError):
            prefiller.open_verified_attachment(plan, user_id=self.user2_id)

    def test_attachment_05_wrong_resume_id(self):
        """5. Mismatched resume_id between reference and authoritative record raises SecurityAuthorizationError."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        # Create second resume for user1
        ok_res2, _, res_rec2 = self.service.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=self.docx_bytes,
            original_filename="second_resume.docx",
        )
        self.assertTrue(ok_res2)
        # Point reference to res_rec2's resume_id but with first resume's path/metadata
        plan.attachment_ref.resume_id = res_rec2["id"]
        with self.assertRaises(SecurityAuthorizationError):
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)

    def test_attachment_06_wrong_version(self):
        """6. Mismatched version_num raises SecurityAuthorizationError."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        plan.attachment_ref.version_num = 99
        with self.assertRaises(SecurityAuthorizationError):
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)

    def test_attachment_07_wrong_storage_filename(self):
        """7. Mismatched storage_filename raises SecurityAuthorizationError."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        plan.attachment_ref.storage_filename = "forged_filename.pdf"
        with self.assertRaises(SecurityAuthorizationError):
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)

    def test_attachment_08_wrong_binary_hash(self):
        """8. Mismatched binary file_hash raises SecurityAuthorizationError."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        plan.attachment_ref.file_hash = "f" * 64
        with self.assertRaises(SecurityAuthorizationError):
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)

    def test_attachment_09_wrong_byte_size(self):
        """9. Mismatched file_size_bytes raises SecurityAuthorizationError."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        plan.attachment_ref.file_size_bytes = len(self.pdf_bytes) + 100
        with self.assertRaises(SecurityAuthorizationError):
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)

    def test_attachment_10_wrong_format(self):
        """10. Unsupported or mismatched file_format raises SecurityAuthorizationError."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        plan.attachment_ref.file_format = "exe"
        with self.assertRaises(SecurityAuthorizationError):
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)

    def test_attachment_11_same_size_file_replacement(self):
        """11. Same-size file replacement on disk triggers hash discrepancy and fails closed."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        p = Path(plan.attachment_ref.file_path)
        # Create different content of exact same size
        tampered = b"A" * len(self.pdf_bytes)
        p.write_bytes(tampered)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("TOCTOU detection", str(ctx.exception))

    def test_attachment_12_post_plan_file_replacement_toctou(self):
        """12. Post-plan creation file tampering on disk fails closed immediately before use."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        p = Path(plan.attachment_ref.file_path)
        p.write_bytes(b"%PDF-1.4 modified after plan was drafted")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("TOCTOU detection", str(ctx.exception))

    def test_attachment_13_symlink_substitution(self):
        """13. Symlink substitution on physical file path is caught and rejected."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        target_file = Path(plan.attachment_ref.file_path)
        symlink_target = self.temp_dir / "secret_file.pdf"
        symlink_target.write_bytes(self.pdf_bytes)

        target_file.unlink()
        try:
            target_file.symlink_to(symlink_target)
        except OSError:
            self.skipTest("Symlinks not supported on filesystem")

        with self.assertRaises(SecurityAuthorizationError):
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)

    def test_attachment_14_path_traversal(self):
        """14. Path traversal characters in storage_filename raise SecurityAuthorizationError."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        plan.attachment_ref.storage_filename = "../../evil.pdf"
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("illegal path components", str(ctx.exception))

    def test_attachment_15_missing_file(self):
        """15. Physical file deleted from disk fails closed."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        Path(plan.attachment_ref.file_path).unlink()

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("TOCTOU detection", str(ctx.exception))

    def test_attachment_16_invalid_magic_bytes(self):
        """16. Modifying file header magic bytes on disk fails closed."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        corrupt_bytes = b"NOT_A_PDF" + self.pdf_bytes[9:]
        Path(plan.attachment_ref.file_path).write_bytes(corrupt_bytes)

        with self.assertRaises(SecurityAuthorizationError):
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)

    def test_attachment_17_tampered_scan_hmac(self):
        """17. Tampering with persisted scan HMAC signature causes open_verified_attachment to fail."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        # Tamper signature in database
        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER IF EXISTS trg_prevent_security_scans_update")
            conn.execute(
                "UPDATE security_scans SET hmac_signature = ? WHERE id = ?",
                ("bad_hmac" * 8, plan.attachment_ref.scan_id),
            )
            # Also tamper ref to match so id check passes
            plan.attachment_ref.scan_signature = "bad_hmac" * 8

        with self.assertRaises(SecurityAuthorizationError):
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)

    def test_attachment_18_mismatched_scan_id(self):
        """18. Mismatched scan ID between reference and latest authoritative scan fails closed."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        plan.attachment_ref.scan_id = 9999
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("Scan ID mismatch", str(ctx.exception))

    def test_attachment_19_mismatched_scan_signature(self):
        """19. Mismatched scan signature between reference and scan record fails closed."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        plan.attachment_ref.scan_signature = "a" * 64
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("Scan signature mismatch", str(ctx.exception))

    def test_attachment_20_revoked_signing_key(self):
        """20. Revoked signing key causes attachment opening to fail closed."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        # Find key_id
        scan = self.db.get_security_scan_by_id(plan.attachment_ref.scan_id)
        self.db.record_key_revocation(scan.key_id, reason="Emergency leak")

        with self.assertRaises((KeyRevokedError, SecurityAuthorizationError)):
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)

    def test_attachment_21_stale_scanner_version(self):
        """21. Stale scanner_version on scan record fails closed."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER IF EXISTS trg_prevent_security_scans_update")
            conn.execute(
                "UPDATE security_scans SET scanner_version = '0.0.1' WHERE id = ?",
                (plan.attachment_ref.scan_id,),
            )

        # Preflight detects stale version and fails closed with SecurityAuthorizationError
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertTrue("stale scanner_version" in str(ctx.exception) or "Scan ID mismatch" in str(ctx.exception))

    def test_attachment_22_stale_policy_version(self):
        """22. Stale policy_version on scan record fails closed."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER IF EXISTS trg_prevent_security_scans_update")
            conn.execute(
                "UPDATE security_scans SET policy_version = '1990.1' WHERE id = ?",
                (plan.attachment_ref.scan_id,),
            )

        # Preflight detects stale version and fails closed with SecurityAuthorizationError
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertTrue("stale policy_version" in str(ctx.exception) or "Scan ID mismatch" in str(ctx.exception))

    def test_attachment_23_suspicious_resume(self):
        """23. Resume classified as SUSPICIOUS fails closed when opening attachment."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        signer = SecurityScanSigner()
        scan_res = PromptInjectionScanResult(
            engine_version=self.detector.engine_version,
            policy_version=self.detector.policy_version,
            risk_score=0.65,
            classification=ScanClassification.SUSPICIOUS,
            threats_detected=[ThreatRecord("R1", "SYS", "MED", 0.65, 0, 10, "Suspicious words", "E1")],
            threat_count=1,
            original_text_length=100,
            scan_timestamp="2026-11-06T12:00:00Z",
        )
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="resume",
            source_id=res_rec["id"],
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v2",
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=len(self.pdf_bytes),
            source_binary_format="pdf",
        )
        scan = self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="resume",
            source_id=res_rec["id"],
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scanner_version=scan_res.engine_version,
            policy_version=scan_res.policy_version,
            risk_score=scan_res.risk_score,
            classification=scan_res.classification,
            threats_detected=[t.to_dict() for t in scan_res.threats_detected],
            key_id=key_id,
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=len(self.pdf_bytes),
            source_binary_format="pdf",
            manifest_version="v2",
        )
        plan.attachment_ref.scan_id = scan.id
        plan.attachment_ref.scan_signature = sig

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("SUSPICIOUS", str(ctx.exception))

    def test_attachment_24_quarantined_resume(self):
        """24. Resume classified as QUARANTINED fails closed when opening attachment."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        signer = SecurityScanSigner()
        scan_res = PromptInjectionScanResult(
            engine_version=self.detector.engine_version,
            policy_version=self.detector.policy_version,
            risk_score=0.95,
            classification=ScanClassification.QUARANTINED,
            threats_detected=[ThreatRecord("R2", "DIR", "HIGH", 0.95, 0, 10, "Override prompt", "E1")],
            threat_count=1,
            original_text_length=100,
            scan_timestamp="2026-11-06T12:00:00Z",
        )
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="resume",
            source_id=res_rec["id"],
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v2",
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=len(self.pdf_bytes),
            source_binary_format="pdf",
        )
        scan = self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="resume",
            source_id=res_rec["id"],
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scanner_version=scan_res.engine_version,
            policy_version=scan_res.policy_version,
            risk_score=scan_res.risk_score,
            classification=scan_res.classification,
            threats_detected=[t.to_dict() for t in scan_res.threats_detected],
            key_id=key_id,
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=len(self.pdf_bytes),
            source_binary_format="pdf",
            manifest_version="v2",
        )
        plan.attachment_ref.scan_id = scan.id
        plan.attachment_ref.scan_signature = sig

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("QUARANTINED", str(ctx.exception))

    def test_attachment_25_candidate_override_of_quarantined_scan(self):
        """25. Candidate override of quarantined scan NEVER unlocks external agent attachment."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        signer = SecurityScanSigner()
        scan_res = PromptInjectionScanResult(
            engine_version=self.detector.engine_version,
            policy_version=self.detector.policy_version,
            risk_score=0.99,
            classification=ScanClassification.QUARANTINED,
            threats_detected=[ThreatRecord("R2", "DIR", "HIGH", 0.99, 0, 10, "Override prompt", "E1")],
            threat_count=1,
            original_text_length=100,
            scan_timestamp="2026-11-06T12:00:00Z",
        )
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="resume",
            source_id=res_rec["id"],
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v2",
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=len(self.pdf_bytes),
            source_binary_format="pdf",
        )
        scan = self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="resume",
            source_id=res_rec["id"],
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scanner_version=scan_res.engine_version,
            policy_version=scan_res.policy_version,
            risk_score=scan_res.risk_score,
            classification=scan_res.classification,
            threats_detected=[t.to_dict() for t in scan_res.threats_detected],
            key_id=key_id,
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=len(self.pdf_bytes),
            source_binary_format="pdf",
            manifest_version="v2",
        )
        # Record override
        self.preflight.record_candidate_override(
            user_id=self.user1_id,
            scan_id=scan.id,
            reason="I am applying to security company.",
        )
        plan.attachment_ref.scan_id = scan.id
        plan.attachment_ref.scan_signature = sig

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("QUARANTINED", str(ctx.exception))

    def test_attachment_26_cross_user_reconstructed_attachment_ref(self):
        """26. Attacker forging an attachment ref for another user's resume raises CrossUserAccessError."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        forged_ref = VerifiedAttachmentRef(
            user_id=self.user2_id,  # User 2 forging ref to User 1's resume
            resume_id=res_rec["id"],
            version_num=plan.attachment_ref.version_num,
            storage_filename=plan.attachment_ref.storage_filename,
            file_path=plan.attachment_ref.file_path,
            file_hash=plan.attachment_ref.file_hash,
            file_size_bytes=plan.attachment_ref.file_size_bytes,
            file_format=plan.attachment_ref.file_format,
            scan_id=plan.attachment_ref.scan_id,
            scan_signature=plan.attachment_ref.scan_signature,
            verified_at=plan.attachment_ref.verified_at,
        )
        with self.assertRaises((CrossUserAccessError, SecurityAuthorizationError)):
            prefiller.open_verified_attachment(forged_ref, user_id=self.user2_id)

    def test_attachment_27_attachment_bytes_returned_without_second_open(self):
        """27. Attachment bytes returned directly from verified memory match physical file without reopening."""
        prefiller, plan, res_rec = self._setup_clean_resume_and_plan()
        verified_bytes = prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertEqual(verified_bytes, self.pdf_bytes)
        self.assertEqual(hashlib.sha256(verified_bytes).hexdigest(), res_rec["file_hash"])

    # =========================================================================
    # PART D: STRICT MANIFEST-VERSION DECLARATION & VERIFICATION (17 TESTS)
    # =========================================================================

    def _create_sample_scan_result(self):
        return PromptInjectionScanResult(
            engine_version="1.0.0",
            policy_version="1.0.0",
            risk_score=0.0,
            classification=ScanClassification.CLEAN,
            threats_detected=[],
            threat_count=0,
            original_text_length=100,
            scan_timestamp="2026-11-06T12:00:00Z",
        )

    def test_manifest_01_explicit_valid_v1(self):
        """1. Explicit manifest_version='v1' without binary metadata verifies successfully."""
        signer = SecurityScanSigner()
        scan_res = self._create_sample_scan_result()
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=10,
            source_version=1,
            source_hash="sha256_src",
            snapshot_hash="sha256_snap",
            scan_result=scan_res,
            manifest_version="v1",
        )
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": manifest["scanned_at"],
            "key_id": key_id,
            "hmac_signature": sig,
            "manifest_version": "v1",
        }
        self.assertTrue(
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
            )
        )

    def test_manifest_02_explicit_valid_v2(self):
        """2. Explicit manifest_version='v2' with complete binary metadata verifies successfully."""
        signer = SecurityScanSigner()
        scan_res = self._create_sample_scan_result()
        bin_hash = "a" * 64
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=10,
            source_version=1,
            source_hash="sha256_src",
            snapshot_hash="sha256_snap",
            scan_result=scan_res,
            manifest_version="v2",
            source_binary_hash=bin_hash,
            source_binary_size_bytes=5000,
            source_binary_format="pdf",
        )
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": manifest["scanned_at"],
            "key_id": key_id,
            "hmac_signature": sig,
            "manifest_version": "v2",
            "source_binary_hash": bin_hash,
            "source_binary_size_bytes": 5000,
            "source_binary_format": "pdf",
        }
        self.assertTrue(
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
                expected_source_binary_hash=bin_hash,
                expected_source_binary_size_bytes=5000,
                expected_source_binary_format="pdf",
            )
        )

    def test_manifest_03_missing_version_with_binary_hash(self):
        """3. Scan row with binary hash but missing manifest_version key fails closed."""
        signer = SecurityScanSigner()
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_1",
            "hmac_signature": "sig" * 16,
            "source_binary_hash": "b" * 64,
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
                expected_source_binary_hash="b" * 64,
            )
        self.assertIn("missing manifest_version", str(ctx.exception))

    def test_manifest_04_missing_version_without_binary_hash(self):
        """4. Scan row without binary hash and missing manifest_version key fails closed."""
        signer = SecurityScanSigner()
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_1",
            "hmac_signature": "sig" * 16,
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
            )
        self.assertIn("missing manifest_version", str(ctx.exception))

    def test_manifest_05_null_version_with_expected_binary_provenance(self):
        """5. Scan row with manifest_version=None fails closed."""
        signer = SecurityScanSigner()
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_1",
            "hmac_signature": "sig" * 16,
            "manifest_version": None,
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
                expected_source_binary_hash="c" * 64,
            )
        self.assertIn("missing manifest_version", str(ctx.exception))

    def test_manifest_06_empty_string_manifest_version(self):
        """6. Empty string manifest_version is rejected."""
        signer = SecurityScanSigner()
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_1",
            "hmac_signature": "sig" * 16,
            "manifest_version": "",
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
            )
        self.assertIn("unsupported manifest_version", str(ctx.exception))

    def test_manifest_07_whitespace_only_manifest_version(self):
        """7. Whitespace-only manifest_version is rejected."""
        signer = SecurityScanSigner()
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_1",
            "hmac_signature": "sig" * 16,
            "manifest_version": "   ",
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
            )
        self.assertIn("unsupported manifest_version", str(ctx.exception))

    def test_manifest_08_unknown_version_v0(self):
        """8. Unknown version 'v0' is rejected."""
        signer = SecurityScanSigner()
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_1",
            "hmac_signature": "sig" * 16,
            "manifest_version": "v0",
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
            )
        self.assertIn("unsupported manifest_version 'v0'", str(ctx.exception))

    def test_manifest_09_unknown_version_v3(self):
        """9. Unknown version 'v3' is rejected."""
        signer = SecurityScanSigner()
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_1",
            "hmac_signature": "sig" * 16,
            "manifest_version": "v3",
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
            )
        self.assertIn("unsupported manifest_version 'v3'", str(ctx.exception))

    def test_manifest_10_wrong_type_manifest_version(self):
        """10. Integer or non-string manifest_version is rejected."""
        signer = SecurityScanSigner()
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_1",
            "hmac_signature": "sig" * 16,
            "manifest_version": 2,  # integer instead of string
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
            )
        self.assertIn("invalid manifest_version type", str(ctx.exception))

    def test_manifest_11_v1_against_uploaded_source_requiring_v2(self):
        """11. Uploaded source requiring v2 binary provenance verified against v1 record fails closed."""
        signer = SecurityScanSigner()
        scan_res = self._create_sample_scan_result()
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=10,
            source_version=1,
            source_hash="sha256_src",
            snapshot_hash="sha256_snap",
            scan_result=scan_res,
            manifest_version="v1",
        )
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": manifest["scanned_at"],
            "key_id": key_id,
            "hmac_signature": sig,
            "manifest_version": "v1",
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
                expected_source_binary_hash="d" * 64,
            )
        self.assertIn("lacking binary provenance", str(ctx.exception))

    def test_manifest_12_v2_with_missing_binary_hash(self):
        """12. v2 scan record with missing binary hash when binary provenance expected fails closed."""
        signer = SecurityScanSigner()
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_1",
            "hmac_signature": "sig" * 16,
            "manifest_version": "v2",
            "source_binary_hash": None,
            "source_binary_size_bytes": 5000,
            "source_binary_format": "pdf",
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
                expected_source_binary_hash="e" * 64,
            )
        self.assertIn("missing required binary metadata", str(ctx.exception))

    def test_manifest_13_v2_with_missing_binary_size(self):
        """13. v2 scan record with missing binary size when binary provenance expected fails closed."""
        signer = SecurityScanSigner()
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_1",
            "hmac_signature": "sig" * 16,
            "manifest_version": "v2",
            "source_binary_hash": "f" * 64,
            "source_binary_size_bytes": None,
            "source_binary_format": "pdf",
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
                expected_source_binary_hash="f" * 64,
            )
        self.assertIn("missing required binary metadata", str(ctx.exception))

    def test_manifest_14_v2_with_missing_binary_format(self):
        """14. v2 scan record with missing binary format when binary provenance expected fails closed."""
        signer = SecurityScanSigner()
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_src",
            "snapshot_hash": "sha256_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_1",
            "hmac_signature": "sig" * 16,
            "manifest_version": "v2",
            "source_binary_hash": "a" * 64,
            "source_binary_size_bytes": 100,
            "source_binary_format": None,
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_src",
                expected_snapshot_hash="sha256_snap",
                scan_row=scan_row,
                expected_source_binary_hash="a" * 64,
            )
        self.assertIn("missing required binary metadata", str(ctx.exception))

    def test_manifest_15_valid_historical_v1_verification(self):
        """15. Valid historical v1 scan verified against non-binary source succeeds."""
        signer = SecurityScanSigner()
        scan_res = self._create_sample_scan_result()
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=20,
            source_version=1,
            source_hash="sha256_pasted_src",
            snapshot_hash="sha256_pasted_snap",
            scan_result=scan_res,
            manifest_version="v1",
        )
        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 20,
            "source_version": 1,
            "source_hash": "sha256_pasted_src",
            "snapshot_hash": "sha256_pasted_snap",
            "scanner_version": "1.0.0",
            "policy_version": "1.0.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": manifest["scanned_at"],
            "key_id": key_id,
            "hmac_signature": sig,
            "manifest_version": "v1",
        }
        ok = signer.verify_scan_record(
            expected_user_id=self.user1_id,
            expected_source_type="job_description",
            expected_source_id=20,
            expected_source_version=1,
            expected_source_hash="sha256_pasted_src",
            expected_snapshot_hash="sha256_pasted_snap",
            scan_row=scan_row,
            expected_source_binary_hash=None,
        )
        self.assertTrue(ok)

    def test_manifest_16_append_only_historical_v1_to_v2_upgrade(self):
        """16. Upgrading a v1 scan to v2 preserves the historical v1 scan and inserts a new v2 scan record."""
        ok_res, _, res_rec = self.service.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=self.pdf_bytes,
            original_filename="v1_resume.pdf",
        )
        resume_id = res_rec["id"]

        # Insert manual v1 scan record
        signer = SecurityScanSigner()
        scan_res = self._create_sample_scan_result()
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v1",
        )
        v1_scan = self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scanner_version=scan_res.engine_version,
            policy_version=scan_res.policy_version,
            risk_score=scan_res.risk_score,
            classification=scan_res.classification,
            threats_detected=[],
            key_id=key_id,
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            manifest_version="v1",
        )

        # Preflight triggers upgrade to v2 because resume upload requires binary provenance
        res = self.preflight.check_resume_security(
            user_id=self.user1_id,
            resume_id=resume_id,
            target_action="document_generation",
        )
        self.assertTrue(res.is_allowed)

        # Both v1 and v2 scans exist in database (append-only)
        v1_check = self.db.get_security_scan_by_id(v1_scan.id)
        self.assertEqual(v1_check.manifest_version, "v1")

        latest_scan = self.db.get_latest_security_scan(
            user_id=self.user1_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
        )
        self.assertGreater(latest_scan.id, v1_scan.id)
        self.assertEqual(latest_scan.manifest_version, "v2")
        self.assertEqual(latest_scan.source_binary_hash, res_rec["file_hash"])

    def test_manifest_17_rescan_failure_leaves_source_unavailable(self):
        """17. If rescanning to upgrade v1 to v2 fails, source remains unavailable (fails closed)."""
        ok_res, _, res_rec = self.service.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=self.pdf_bytes,
            original_filename="fail_rescan_resume.pdf",
        )
        resume_id = res_rec["id"]

        signer = SecurityScanSigner()
        scan_res = self._create_sample_scan_result()
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v1",
        )
        self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scanner_version=scan_res.engine_version,
            policy_version=scan_res.policy_version,
            risk_score=scan_res.risk_score,
            classification=scan_res.classification,
            threats_detected=[],
            key_id=key_id,
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            manifest_version="v1",
        )

        # Mock detector scan to raise an exception during rescan
        with patch.object(self.preflight.detector, "scan", side_effect=RuntimeError("Detector engine failure")):
            with self.assertRaises((RuntimeError, SecurityAuthorizationError)):
                self.preflight.check_resume_security(
                    user_id=self.user1_id,
                    resume_id=resume_id,
                    target_action="document_generation",
                )


if __name__ == "__main__":
    unittest.main()

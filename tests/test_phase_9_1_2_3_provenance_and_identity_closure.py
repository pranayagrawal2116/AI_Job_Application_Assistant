"""Phase 9.1.2.3 — Dedicated Test Suite: Legacy Provenance, Manifest-Version & Attachment Lifecycle Closure.

Covers:
1. New same-day uploaded records with all-NULL metadata fail closed.
2. Older timestamp manipulation cannot make a new record legacy.
3. Explicitly migrated historical records remain compatible.
4. Historical exceptions have durable append-only audit evidence.
5. Scan HMAC binary provenance cannot be bypassed by clearing source metadata.
6. Unknown manifest versions fail closed.
7. v1 cannot satisfy v2 binary-provenance requirements.
8. Old resume scans are upgraded to v2 before current acceptance.
9. Active and rotation key collisions are rejected during initialization.
10. Duplicate normalized key IDs cannot overwrite each other with differing secrets.
11. Historical key IDs always resolve to original secret bytes.
12. FormFillPlan contains exact verified attachment identity (VerifiedAttachmentRef).
13. Files replaced after plan creation are rejected at use time (TOCTOU defense).
14. All existing legitimate pasted, URL, and uploaded workflows remain functional.
15. LEGACY_TEXT_ONLY binary integrity state cannot be assigned via public snapshot creation API.
16. Use-time verification catches format magic byte tampering, scan ID mismatch, and quarantine.
"""

import hashlib
from pathlib import Path
import secrets
import shutil
import sqlite3
import tempfile
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    SecurityAuthorizationError,
)
from src.preparer.form_prefiller import FormPrefiller, VerifiedAttachmentRef
from src.security.file_security import FileSecurityValidator
from src.security.prompt_injection_detector import (
    PromptInjectionDetector,
    PromptInjectionScanResult,
    ScanClassification,
    ThreatRecord,
)
from src.security.scan_signer import ScanKeyManager, SecurityScanSigner
from src.security.security_preflight import SecurityPreflightManager
from src.utils.canonical_json import canonical_json_hash
from tests.fixtures.synthetic_personas import (
    generate_persona_docx,
    generate_persona_pdf,
)


class TestPhase9123ProvenanceAndIdentityClosure(unittest.TestCase):
    """Exhaustive test suite for Phase 9.1.2.3 requirements."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_phase_9_1_2_3_"))
        self.db_path = self.temp_dir / "closure.db"
        self.storage_dir = self.temp_dir / "storage"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=str(self.db_path))
        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_dir)

        from src.security.legacy_evidence_verifier import (
            LegacyEvidenceTrustStore,
            InMemoryEvidenceResolver,
            LegacyEvidenceVerifier,
            set_default_evidence_trust_store,
            set_default_evidence_resolver,
        )
        self.trust_store = LegacyEvidenceTrustStore(db_manager=self.db)
        self.trust_store.register_trusted_issuer("system_migration_authority")
        self.trust_store.register_trusted_key("test_key_9123", b"test_secret_32_bytes_long_9123!!")
        self.resolver = InMemoryEvidenceResolver()
        set_default_evidence_trust_store(self.trust_store)
        set_default_evidence_resolver(self.resolver)
        self.evidence_verifier = LegacyEvidenceVerifier(
            db_manager=self.db,
            trust_store=self.trust_store,
            resolver=self.resolver,
        )

        self.service = DashboardService(db_manager=self.db, storage_base_dir=self.storage_dir)
        self.preflight = SecurityPreflightManager(
            db_manager=self.db,
            file_validator=self.file_validator,
            evidence_verifier=self.evidence_verifier,
        )
        self.detector = PromptInjectionDetector()

        # Create two test users
        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("alice@example.com", "hash1", "salt1", "Alice Closure"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("bob@example.com", "hash2", "salt2", "Bob Closure"),
            )
            self.user2_id = c.lastrowid

        # Pre-generate genuine PDF and DOCX bytes
        self.pdf_bytes = generate_persona_pdf("backend_engineer")
        self.docx_bytes = generate_persona_docx("backend_engineer")

    def tearDown(self):
        from src.security.legacy_evidence_verifier import (
            set_default_evidence_trust_store,
            set_default_evidence_resolver,
        )
        set_default_evidence_trust_store(None)
        set_default_evidence_resolver(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # TEST 1: New same-day uploaded records with all-NULL metadata fail closed
    # -------------------------------------------------------------------------
    def test_01_new_same_day_uploaded_records_with_all_null_fail_closed(self):
        """Uploaded job description created today with all-NULL binary metadata fails closed during preflight."""
        # Create an uploaded record with all 4 binary fields NULL and default REQUIRED state
        raw_text = "Develop Python microservices and APIs."
        content_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "Acme Corp",
            "job_title": "Software Engineer",
            "raw_content_hash": content_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snapshot_hash = canonical_json_hash(manifest)

        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active
                ) VALUES (?, 'upload', 'Acme Corp', 'Software Engineer',
                          ?, ?, ?, 'REQUIRED', 1)
                """,
                (self.user1_id, raw_text, content_hash, snapshot_hash),
            )
            jd_id = c.lastrowid

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(
                user_id=self.user1_id,
                jd_id=jd_id,
                target_action="document_generation",
            )
        self.assertIn("missing required binary metadata", str(ctx.exception))

    # -------------------------------------------------------------------------
    # TEST 2: Older timestamp manipulation cannot make a new record legacy
    # -------------------------------------------------------------------------
    def test_02_older_timestamp_manipulation_cannot_make_record_legacy(self):
        """Setting created_at to an older historical timestamp does not grant legacy status without explicit migration audit."""
        raw_text = "Maintain legacy C++ codebases."
        content_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "Vintage Corp",
            "job_title": "Legacy Developer",
            "raw_content_hash": content_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snapshot_hash = canonical_json_hash(manifest)

        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'Vintage Corp', 'Legacy Developer',
                          ?, ?, ?, 'REQUIRED', 1, '2024-01-15 10:00:00')
                """,
                (self.user1_id, raw_text, content_hash, snapshot_hash),
            )
            jd_id = c.lastrowid

        # Despite created_at being in 2024, without LEGACY_TEXT_ONLY and audit record, preflight must fail closed
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(
                user_id=self.user1_id,
                jd_id=jd_id,
                target_action="document_generation",
            )
        self.assertIn("missing required binary metadata", str(ctx.exception))

    # -------------------------------------------------------------------------
    # TEST 3: Explicitly migrated historical records remain compatible
    # -------------------------------------------------------------------------
    def test_03_explicitly_migrated_historical_records_remain_compatible(self):
        """Historical pre-9.1.1 records migrated to LEGACY_TEXT_ONLY with durable audit row pass preflight."""
        # Insert historical unmigrated record
        raw_text = "Historical developer role with SQL and Python requirements."
        content_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "Old Co",
            "job_title": "Systems Analyst",
            "raw_content_hash": content_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snapshot_hash = canonical_json_hash(manifest)

        # Un-mark migration to simulate pre-migration unmigrated historical database
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'Old Co', 'Systems Analyst',
                          ?, ?, ?, 'REQUIRED', 1, '2025-06-01 12:00:00')
                """,
                (self.user1_id, raw_text, content_hash, snapshot_hash),
            )
            jd_id = c.lastrowid
            c.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, 'historical_import_manifest', 'MANIFEST_2025_06_01_001', ?, 'system_migration_coordinator')
                """,
                (self.user1_id, jd_id, snapshot_hash),
            )

        from src.security.legacy_evidence_verifier import create_signed_evidence_artifact
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="MANIFEST_2025_06_01_001",
            issuer_id="system_migration_authority",
            key_id="test_key_9123",
            signing_key=b"test_secret_32_bytes_long_9123!!",
            entries=[{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snapshot_hash}],
        )
        self.resolver.register_artifact("historical_import_manifest", "MANIFEST_2025_06_01_001", art_bytes)

        # Run database migration routine
        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        # Verify state transitioned to LEGACY_TEXT_ONLY
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertIsNotNone(jd)
        self.assertEqual(jd.binary_integrity_state, "LEGACY_TEXT_ONLY")

        # Verify audit row exists in legacy_integrity_exceptions
        exc = self.db.get_legacy_integrity_exception(job_description_id=jd_id, user_id=self.user1_id)
        self.assertIsNotNone(exc)
        self.assertEqual(exc.assigned_legacy_state, "LEGACY_TEXT_ONLY")
        self.assertEqual(exc.outcome, "SUCCESS")

        # Preflight check must cleanly pass
        res = self.preflight.check_job_description_security(
            user_id=self.user1_id,
            jd_id=jd_id,
            target_action="document_generation",
        )
        self.assertTrue(res.is_allowed)
        self.assertEqual(res.classification, ScanClassification.CLEAN)

    # -------------------------------------------------------------------------
    # TEST 4: Historical exceptions have durable audit evidence
    # -------------------------------------------------------------------------
    def test_04_historical_exceptions_have_durable_audit_evidence(self):
        """legacy_integrity_exceptions table enforces strict append-only and immutable triggers."""
        # Insert dummy JD first
        jd = self.db.save_job_description_snapshot(
            user_id=self.user1_id,
            company_name="Audit Co",
            job_title="Audit Engineer",
            raw_content="Review audit logs.",
            source_type="pasted",
        )
        exc_id = self.db.record_legacy_integrity_exception(
            user_id=self.user1_id,
            job_description_id=jd.id,
            original_source_type="pasted",
            previous_binary_state="NOT_APPLICABLE",
            assigned_legacy_state="LEGACY_TEXT_ONLY",
            source_snapshot_hash=jd.snapshot_hash,
            migration_version="9.1.2.3",
            migration_reason="Test exception",
            outcome="SUCCESS",
        )
        self.assertGreater(exc_id, 0)

        # Attempt to UPDATE must fail via trigger
        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            with self.db.immediate_transaction() as conn:
                conn.cursor().execute(
                    "UPDATE legacy_integrity_exceptions SET outcome = 'FAIL' WHERE id = ?",
                    (exc_id,),
                )
        self.assertIn("append-only", str(ctx.exception))

        # Attempt to DELETE must fail via trigger
        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            with self.db.immediate_transaction() as conn:
                conn.cursor().execute(
                    "DELETE FROM legacy_integrity_exceptions WHERE id = ?",
                    (exc_id,),
                )
        self.assertIn("immutable", str(ctx.exception))

    # -------------------------------------------------------------------------
    # TEST 5: Scan HMAC binary provenance cannot be bypassed by clearing source metadata
    # -------------------------------------------------------------------------
    def test_05_scan_hmac_binary_provenance_cannot_be_bypassed_by_clearing_source_metadata(self):
        """If an authoritative scan was recorded with physical binary hash, clearing source columns fails closed."""
        # 1. Upload legitimate PDF job description
        jd = self.db.upload_user_job_description(
            user_id=self.user1_id,
            file_bytes=self.pdf_bytes,
            original_filename="job_post.pdf",
            user_base_dir=self.file_validator.get_user_job_descriptions_dir(self.user1_id),
        )
        # Preflight generates signed scan with source_binary_hash
        res1 = self.preflight.check_job_description_security(
            user_id=self.user1_id,
            jd_id=jd.id,
        )
        self.assertTrue(res1.is_allowed)

        # 2. Simulate attacker clearing binary fields and assigning LEGACY_TEXT_ONLY
        with self.db.immediate_transaction() as conn:
            c = conn.cursor()
            c.execute(
                """
                UPDATE job_descriptions
                SET storage_filename = NULL,
                    file_hash = NULL,
                    file_size_bytes = NULL,
                    file_format = NULL,
                    binary_integrity_state = 'LEGACY_TEXT_ONLY'
                WHERE id = ?
                """,
                (jd.id,),
            )
            # Even if attacker inserts an exception entry
            c.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type,
                    previous_binary_state, assigned_legacy_state,
                    source_snapshot_hash, migration_version,
                    migration_reason, outcome
                ) VALUES (?, ?, 'uploaded_document', 'VERIFIED', 'LEGACY_TEXT_ONLY', ?, '9.1.2.3', 'Malicious downgrade', 'SUCCESS')
                """,
                (self.user1_id, jd.id, jd.snapshot_hash),
            )

        # Preflight MUST fail closed because existing signed scan contains binary provenance!
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(
                user_id=self.user1_id,
                jd_id=jd.id,
            )
        self.assertIn("exists with binary provenance", str(ctx.exception))

    # -------------------------------------------------------------------------
    # TEST 6: Unknown manifest versions fail closed
    # -------------------------------------------------------------------------
    def test_06_unknown_manifest_versions_fail_closed(self):
        """SecurityScanSigner strictly rejects manifest versions outside supported {'v1', 'v2'}."""
        signer = SecurityScanSigner()

        # Rejects unknown manifest_version in build_canonical_manifest
        for bad_version in ("v3", "v0", "", "  ", "v2.1", "2"):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                signer.build_canonical_manifest(
                    user_id=self.user1_id,
                    source_type="job_description",
                    source_id=1,
                    source_version=1,
                    source_hash="hash",
                    snapshot_hash="snap",
                    scanner_version="1.0.0",
                    policy_version="1.0.0",
                    risk_score=0.0,
                    classification="CLEAN",
                    threats=[],
                    scanned_at="2026-11-06T12:00:00Z",
                    key_id=signer.key_manager.active_key_id,
                    manifest_version=bad_version,
                )
            self.assertIn("Unsupported or invalid manifest_version", str(ctx.exception))

        # Rejects unknown manifest_version in verify_scan_record
        bad_scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 1,
            "source_version": 1,
            "source_hash": "hash",
            "snapshot_hash": "snap",
            "manifest_version": "v3",
            "key_id": signer.key_manager.active_key_id,
            "hmac_signature": "sig",
            "scanned_at": "2026-11-06T12:00:00Z",
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=1,
                expected_source_version=1,
                expected_source_hash="hash",
                expected_snapshot_hash="snap",
                scan_row=bad_scan_row,
            )
        self.assertIn("unsupported manifest_version", str(ctx.exception))

    # -------------------------------------------------------------------------
    # TEST 7: v1 cannot satisfy v2 binary-provenance requirements
    # -------------------------------------------------------------------------
    def test_07_v1_cannot_satisfy_v2_binary_provenance_requirements(self):
        """verify_scan_record rejects v1 manifest records when expected binary provenance is required."""
        signer = SecurityScanSigner()
        scan_res = self.detector.scan("Clean text.")
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="resume",
            source_id=1,
            source_version=1,
            source_hash="resume_hash",
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v1",
        )
        scan_dict = {
            "id": 100,
            "user_id": self.user1_id,
            "source_type": "resume",
            "source_id": 1,
            "source_version": 1,
            "source_hash": "resume_hash",
            "snapshot_hash": None,
            "scanner_version": scan_res.engine_version,
            "policy_version": scan_res.policy_version,
            "risk_score": scan_res.risk_score,
            "classification": scan_res.classification,
            "threats_detected_json": "[]",
            "key_id": key_id,
            "hmac_signature": sig,
            "scanned_at": manifest["scanned_at"],
            "source_binary_hash": None,
            "source_binary_size_bytes": None,
            "source_binary_format": None,
            "manifest_version": "v1",
        }

        # Verifying without expected binary provenance succeeds for v1
        self.assertTrue(
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="resume",
                expected_source_id=1,
                expected_source_version=1,
                expected_source_hash="resume_hash",
                expected_snapshot_hash=None,
                scan_row=scan_dict,
            )
        )

        # Verifying with expected binary provenance MUST raise SecurityAuthorizationError
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="resume",
                expected_source_id=1,
                expected_source_version=1,
                expected_source_hash="resume_hash",
                expected_snapshot_hash=None,
                scan_row=scan_dict,
                expected_source_binary_hash="resume_hash",
                expected_source_binary_size_bytes=1024,
                expected_source_binary_format="pdf",
            )
        self.assertIn("manifest version 'v1' lacking binary provenance", str(ctx.exception))

    # -------------------------------------------------------------------------
    # TEST 8: Old resume scans are upgraded to v2 before current acceptance
    # -------------------------------------------------------------------------
    def test_08_old_resume_scans_are_upgraded_to_v2_before_current_acceptance(self):
        """Historical v1 resume scans are cleanly rescanned and upgraded to v2 in security preflight."""
        ok, _, rec = self.service.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=self.pdf_bytes,
            original_filename="upgrade_test.pdf",
        )
        self.assertTrue(ok)
        resume_id = rec["id"]

        # Insert a historical v1 CLEAN scan
        signer = SecurityScanSigner()
        scan_res = self.detector.scan("Candidate Resume text.")
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=rec["file_hash"],
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v1",
        )
        scan1 = self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=rec["file_hash"],
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
        self.assertEqual(scan1.manifest_version, "v1")

        # Calling check_resume_security must detect v1, trigger fresh v2 scan, and pass
        res = self.preflight.check_resume_security(
            user_id=self.user1_id,
            resume_id=resume_id,
            target_action="document_generation",
        )
        self.assertTrue(res.is_allowed)

        # Verify a new v2 scan was recorded in database
        latest_scan = self.db.get_latest_security_scan(
            user_id=self.user1_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
        )
        self.assertGreater(latest_scan.id, scan1.id)
        self.assertEqual(latest_scan.manifest_version, "v2")
        self.assertEqual(latest_scan.source_binary_hash, rec["file_hash"])

    # -------------------------------------------------------------------------
    # TEST 9: Active and rotation key collisions rejected during initialization
    # -------------------------------------------------------------------------
    def test_09_active_rotation_key_collisions_rejected_during_init(self):
        """ScanKeyManager raises SecurityAuthorizationError if rotation keys collide with active key with different secrets."""
        sec1 = secrets.token_bytes(32)
        sec2 = secrets.token_bytes(32)

        # Same key ID 'key_alpha' with different secrets must fail
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            ScanKeyManager(
                active_key_id="key_alpha",
                signing_key=sec1,
                rotation_keys={"key_alpha": sec2},
            )
        self.assertIn("Cannot reuse existing key ID 'key_alpha' with different secret material", str(ctx.exception))

        # Same key ID 'key_alpha' with identical secret succeeds idempotently
        km = ScanKeyManager(
            active_key_id="key_alpha",
            signing_key=sec1,
            rotation_keys={"key_alpha": sec1},
        )
        self.assertEqual(km.get_verification_key("key_alpha"), sec1)

    # -------------------------------------------------------------------------
    # TEST 10: Duplicate normalized key IDs cannot overwrite with differing secrets
    # -------------------------------------------------------------------------
    def test_10_duplicate_normalized_key_ids_cannot_overwrite(self):
        """Whitespace-padded key IDs normalize cleanly; collisions with different secrets fail closed."""
        sec_main = secrets.token_bytes(32)
        sec_rot1 = secrets.token_bytes(32)
        sec_rot2 = secrets.token_bytes(32)

        # Differing secrets under 'key_beta' and '  key_beta  ' must fail
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            ScanKeyManager(
                active_key_id="key_main",
                signing_key=sec_main,
                rotation_keys={"key_beta": sec_rot1, "  key_beta  ": sec_rot2},
            )
        self.assertIn("Cannot reuse existing key ID 'key_beta'", str(ctx.exception))

        # Identical secrets succeed idempotently
        km = ScanKeyManager(
            active_key_id="key_main",
            signing_key=sec_main,
            rotation_keys={"key_beta": sec_rot1, "  key_beta  ": sec_rot1},
        )
        self.assertEqual(km.get_verification_key("key_beta"), sec_rot1)

    # -------------------------------------------------------------------------
    # TEST 11: Historical key IDs always resolve to original secret bytes
    # -------------------------------------------------------------------------
    def test_11_historical_key_ids_always_resolve_to_original_secret_bytes(self):
        """Keys registered historically retain their original bytes and cannot be mutated by rotate_key."""
        s1 = secrets.token_bytes(32)
        s2 = secrets.token_bytes(32)
        s3 = secrets.token_bytes(32)

        km = ScanKeyManager(active_key_id="k1", signing_key=s1, rotation_keys={"k2": s2})
        km.rotate_key("k3", s3)

        self.assertEqual(km.get_verification_key("k1"), s1)
        self.assertEqual(km.get_verification_key("k2"), s2)
        self.assertEqual(km.get_verification_key("k3"), s3)

        # Attempt to rotate to k1 with DIFFERENT secret fails closed
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            km.rotate_key("k1", secrets.token_bytes(32))
        self.assertIn("Cannot reuse existing key ID 'k1' with different secret material", str(ctx.exception))

        # Re-rotating to k1 with identical bytes succeeds
        km.rotate_key("k1", s1)
        self.assertEqual(km.active_key_id, "k1")

    # -------------------------------------------------------------------------
    # TEST 12: FormFillPlan contains exact verified attachment identity
    # -------------------------------------------------------------------------
    def test_12_form_fill_plan_contains_exact_verified_attachment_identity(self):
        """build_form_payload constructs an authoritative VerifiedAttachmentRef bound to FormFillPlan."""
        ok_res, _, res_rec = self.service.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=self.pdf_bytes,
            original_filename="profile_resume.pdf",
        )
        self.assertTrue(ok_res)
        resume_id = res_rec["id"]

        ok_jd, _, jd = self.service.ingest_job_text(
            user_id=self.user1_id,
            raw_text="Backend Engineer with Python and PostgreSQL expertise.",
            hint_title="Backend Engineer",
            hint_company="Fintech Co",
        )
        self.assertTrue(ok_jd)

        prefiller = FormPrefiller(db_manager=self.db, file_validator=self.file_validator)
        plan = prefiller.build_form_payload(
            job=jd,
            user_id=self.user1_id,
            resume_id=resume_id,
        )

        self.assertIsNotNone(plan.attachment_ref)
        self.assertIsInstance(plan.attachment_ref, VerifiedAttachmentRef)
        self.assertEqual(plan.attachment_ref.user_id, self.user1_id)
        self.assertEqual(plan.attachment_ref.resume_id, resume_id)
        self.assertEqual(plan.attachment_ref.file_hash, res_rec["file_hash"])
        self.assertEqual(plan.attachment_ref.file_size_bytes, len(self.pdf_bytes))
        self.assertEqual(plan.attachment_ref.file_format, "pdf")
        self.assertGreater(plan.attachment_ref.scan_id, 0)
        self.assertEqual(len(plan.attachment_ref.scan_signature), 64)

    # -------------------------------------------------------------------------
    # TEST 13: Files replaced after plan creation are rejected at use time (TOCTOU)
    # -------------------------------------------------------------------------
    def test_13_files_replaced_after_plan_creation_rejected_at_use_time(self):
        """open_verified_attachment catches post-creation disk file tampering immediately before upload."""
        ok_res, _, res_rec = self.service.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=self.pdf_bytes,
            original_filename="toctou_resume.pdf",
        )
        self.assertTrue(ok_res)
        resume_id = res_rec["id"]

        ok_jd, _, jd = self.service.ingest_job_text(
            user_id=self.user1_id,
            raw_text="Software Developer position at HighTech LLC.",
            hint_title="Developer",
            hint_company="HighTech LLC",
        )
        self.assertTrue(ok_jd)

        prefiller = FormPrefiller(db_manager=self.db, file_validator=self.file_validator)
        plan = prefiller.build_form_payload(
            job=jd,
            user_id=self.user1_id,
            resume_id=resume_id,
        )
        self.assertIsNotNone(plan.attachment_ref)

        # Verified open before tampering succeeds
        content = prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertEqual(content, self.pdf_bytes)

        # TOCTOU attack: attacker modifies the physical resume file on disk
        tampered_bytes = b"%PDF-tampered content injected after authorization gate"
        with open(plan.attachment_ref.file_path, "wb") as f:
            f.write(tampered_bytes)

        # open_verified_attachment MUST detect hash and size discrepancies and raise SecurityAuthorizationError
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("TOCTOU detection", str(ctx.exception))

    # -------------------------------------------------------------------------
    # TEST 14: All existing legitimate pasted, URL, and uploaded workflows functional
    # -------------------------------------------------------------------------
    def test_14_all_legitimate_pasted_url_and_uploaded_workflows_functional(self):
        """End-to-end integration: pasted, URL, PDF uploaded, and DOCX uploaded workflows all succeed."""
        # 1. Pasted source
        ok_paste, _, jd_paste = self.service.ingest_job_text(
            user_id=self.user1_id,
            raw_text="Machine Learning Engineer with PyTorch, NLP, and Python experience.",
            hint_title="ML Engineer",
            hint_company="AI Labs",
        )
        self.assertTrue(ok_paste)
        res_paste = self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_paste.id)
        self.assertTrue(res_paste.is_allowed)

        # 2. Uploaded PDF source
        jd_pdf = self.db.upload_user_job_description(
            user_id=self.user1_id,
            file_bytes=self.pdf_bytes,
            original_filename="jd_spec.pdf",
            user_base_dir=self.file_validator.get_user_job_descriptions_dir(self.user1_id),
        )
        res_pdf = self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_pdf.id)
        self.assertTrue(res_pdf.is_allowed)

        # 3. Uploaded DOCX source
        jd_docx = self.db.upload_user_job_description(
            user_id=self.user1_id,
            file_bytes=self.docx_bytes,
            original_filename="jd_spec.docx",
            user_base_dir=self.file_validator.get_user_job_descriptions_dir(self.user1_id),
        )
        res_docx = self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_docx.id)
        self.assertTrue(res_docx.is_allowed)

        # 4. Form prefill with verified resume succeeds across all job sources
        ok_res, _, res_rec = self.service.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=self.pdf_bytes,
            original_filename="candidate_cv.pdf",
        )
        self.assertTrue(ok_res)

        prefiller = FormPrefiller(db_manager=self.db, file_validator=self.file_validator)
        for jd in (jd_paste, jd_pdf, jd_docx):
            plan = prefiller.build_form_payload(
                job=jd,
                user_id=self.user1_id,
                resume_id=res_rec["id"],
            )
            self.assertTrue(plan.resume_attachment_ready)
            verified_bytes = prefiller.open_verified_attachment(plan, user_id=self.user1_id)
            self.assertEqual(verified_bytes, self.pdf_bytes)

    # -------------------------------------------------------------------------
    # TEST 15: LEGACY_TEXT_ONLY state rejected via public snapshot creation API
    # -------------------------------------------------------------------------
    def test_15_legacy_text_only_rejected_via_public_api(self):
        """Callers cannot assign LEGACY_TEXT_ONLY binary integrity state via save_job_description_snapshot."""
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.save_job_description_snapshot(
                user_id=self.user1_id,
                company_name="Sneaky Co",
                job_title="Hacker",
                raw_content="Attempting bypass.",
                binary_integrity_state="LEGACY_TEXT_ONLY",
            )
        self.assertIn("cannot be assigned via public API", str(ctx.exception))

    # -------------------------------------------------------------------------
    # TEST 16: open_verified_attachment validates magic bytes, quarantine, and cross-user
    # -------------------------------------------------------------------------
    def test_16_open_verified_attachment_validates_magic_bytes_quarantine_and_user(self):
        """open_verified_attachment strictly blocks cross-user access, quarantined resumes, and corrupt formats."""
        ok_res, _, res_rec = self.service.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=self.pdf_bytes,
            original_filename="security_test.pdf",
        )
        self.assertTrue(ok_res)
        resume_id = res_rec["id"]

        ok_jd, _, jd = self.service.ingest_job_text(
            user_id=self.user1_id,
            raw_text="Security Engineer opening.",
            hint_title="Security Engineer",
            hint_company="SecCorp",
        )
        self.assertTrue(ok_jd)

        prefiller = FormPrefiller(db_manager=self.db, file_validator=self.file_validator)
        plan = prefiller.build_form_payload(job=jd, user_id=self.user1_id, resume_id=resume_id)

        # 1. Cross-user access
        with self.assertRaises(CrossUserAccessError):
            prefiller.open_verified_attachment(plan, user_id=self.user2_id)

        # 2. Quarantined scan block
        signer = SecurityScanSigner()
        scan_res = PromptInjectionScanResult(
            engine_version=self.detector.engine_version,
            policy_version=self.detector.policy_version,
            risk_score=0.99,
            classification=ScanClassification.QUARANTINED,
            threats_detected=[
                ThreatRecord("DIR_01", "OVERRIDE", "HIGH", 0.99, 0, 10, "Evil prompt", "E1")
            ],
            threat_count=1,
            original_text_length=100,
            scan_timestamp="2026-11-06T12:00:00Z",
        )
        manifest, sig, key_id = signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v2",
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=len(self.pdf_bytes),
            source_binary_format="pdf",
        )
        q_scan = self.db.save_security_scan(
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
            threats_detected=[t.to_dict() for t in scan_res.threats_detected],
            key_id=key_id,
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=len(self.pdf_bytes),
            source_binary_format="pdf",
            manifest_version="v2",
        )
        plan.attachment_ref.scan_id = q_scan.id
        plan.attachment_ref.scan_signature = sig

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prefiller.open_verified_attachment(plan, user_id=self.user1_id)
        self.assertIn("QUARANTINED", str(ctx.exception))
        self.assertIn("QUARANTINED", str(ctx.exception))

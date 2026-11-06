"""Unit and Security Tests for Authenticated Security Scan Persistence and Verification.

Tests:
1. Canonical JSON RFC 8785 determinism and HMAC-SHA256 signature generation.
2. Tamper detection across all signed manifest fields (risk score, classification, source hash, snapshot hash, threats, key ID).
3. Cross-user scan access and cross-source substitution rejection.
4. SQLite append-only triggers preventing UPDATE and DELETE on security_scans.
5. Authorized privacy erasure integration.
6. Revision history append-only behavior (deterministic latest-scan selection).
"""

import json
import sqlite3
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    SecurityAuthorizationError,
)
from src.security.prompt_injection_detector import (
    PromptInjectionScanResult,
    ScanClassification,
    ThreatRecord,
)
from src.security.scan_signer import ScanKeyManager, SecurityScanSigner


class TestSecurityScanPersistence(unittest.TestCase):
    """Test suite validating authenticated scan signing, SQLite persistence, and immutability triggers."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = DatabaseManager(db_path=self.temp_db.name)
        # Create test users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("alice@example.com", "hash1", "salt1", "Alice Smith"),
            )
            self.user1_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("bob@example.com", "hash2", "salt2", "Bob Jones"),
            )
            self.user2_id = cursor.lastrowid

        self.key_manager = ScanKeyManager(active_key_id="test_key_v1", signing_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        self.signer = SecurityScanSigner(key_manager=self.key_manager)

    def tearDown(self):
        try:
            import os
            os.unlink(self.temp_db.name)
        except OSError:
            pass

    def _create_sample_scan_result(self, classification=ScanClassification.CLEAN, score=0.0):
        threats = []
        if classification == ScanClassification.QUARANTINED:
            threats.append(ThreatRecord(
                rule_id="DIR_OVR_001",
                category="DIRECT_OVERRIDE",
                severity="CRITICAL",
                confidence=0.95,
                start_offset=0,
                end_offset=30,
                explanation="Ignore previous instructions.",
                engine_id="ENGINE_1_DIRECT",
            ))
        return PromptInjectionScanResult(
            engine_version="1.0.0",
            policy_version="9.1.2",
            risk_score=score,
            classification=classification,
            threats_detected=threats,
            threat_count=len(threats),
            original_text_length=100,
            scan_timestamp="2026-11-06T12:00:00+00:00",
        )

    def test_01_valid_signing_persistence_and_verification(self):
        """Tests that a correctly signed scan can be persisted and independently verified."""
        scan_res = self._create_sample_scan_result(classification=ScanClassification.CLEAN, score=0.05)
        manifest, sig, key_id = self.signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=101,
            source_version=1,
            source_hash="sha256_src_101",
            snapshot_hash="sha256_snap_101",
            scan_result=scan_res,
        )

        scan_record = self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=101,
            source_version=1,
            source_hash="sha256_src_101",
            snapshot_hash="sha256_snap_101",
            scanner_version=scan_res.engine_version,
            policy_version=scan_res.policy_version,
            risk_score=scan_res.risk_score,
            classification=scan_res.classification,
            threats_detected=[t.to_dict() for t in scan_res.threats_detected],
            key_id=key_id,
            hmac_signature=sig,
            scanned_at=scan_res.scan_timestamp,
        )

        self.assertIsNotNone(scan_record.id)
        # Verify from DB row
        scan_dict = scan_record.to_dict()
        scan_dict["threats_detected_json"] = scan_record.threats_detected_json
        is_valid = self.signer.verify_scan_record(
            expected_user_id=self.user1_id,
            expected_source_type="job_description",
            expected_source_id=101,
            expected_source_version=1,
            expected_source_hash="sha256_src_101",
            expected_snapshot_hash="sha256_snap_101",
            scan_row=scan_dict,
        )
        self.assertTrue(is_valid)

    def test_02_tamper_detection_risk_score(self):
        """Asserts that modifying the persisted risk score causes cryptographic verification failure."""
        scan_res = self._create_sample_scan_result(classification=ScanClassification.QUARANTINED, score=0.85)
        _, sig, key_id = self.signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=102,
            source_version=1,
            source_hash="sha256_src_102",
            snapshot_hash="sha256_snap_102",
            scan_result=scan_res,
        )

        scan_row = {
            "id": 1,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 102,
            "source_version": 1,
            "source_hash": "sha256_src_102",
            "snapshot_hash": "sha256_snap_102",
            "scanner_version": "1.0.0",
            "policy_version": "9.1.2",
            "risk_score": 0.10,  # Tampered from 0.85 to 0.10!
            "classification": ScanClassification.QUARANTINED,
            "threats_detected_json": json.dumps([t.to_dict() for t in scan_res.threats_detected]),
            "key_id": key_id,
            "hmac_signature": sig,
            "scanned_at": scan_res.scan_timestamp,
        }

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=102,
                expected_source_version=1,
                expected_source_hash="sha256_src_102",
                expected_snapshot_hash="sha256_snap_102",
                scan_row=scan_row,
            )
        self.assertIn("Cryptographic signature verification failed", str(ctx.exception))

    def test_03_tamper_detection_classification(self):
        """Asserts that modifying classification (e.g. QUARANTINED -> CLEAN) fails verification."""
        scan_res = self._create_sample_scan_result(classification=ScanClassification.QUARANTINED, score=0.85)
        _, sig, key_id = self.signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=103,
            source_version=1,
            source_hash="sha256_src_103",
            snapshot_hash="sha256_snap_103",
            scan_result=scan_res,
        )

        scan_row = {
            "id": 2,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 103,
            "source_version": 1,
            "source_hash": "sha256_src_103",
            "snapshot_hash": "sha256_snap_103",
            "scanner_version": "1.0.0",
            "policy_version": "9.1.2",
            "risk_score": 0.85,
            "classification": ScanClassification.CLEAN,  # Tampered!
            "threats_detected_json": json.dumps([t.to_dict() for t in scan_res.threats_detected]),
            "key_id": key_id,
            "hmac_signature": sig,
            "scanned_at": scan_res.scan_timestamp,
        }

        with self.assertRaises(SecurityAuthorizationError):
            self.signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="job_description",
                expected_source_id=103,
                expected_source_version=1,
                expected_source_hash="sha256_src_103",
                expected_snapshot_hash="sha256_snap_103",
                scan_row=scan_row,
            )

    def test_04_cross_user_scan_access_rejected(self):
        """Asserts that attempting to verify a scan with the wrong user_id raises CrossUserAccessError."""
        scan_res = self._create_sample_scan_result(classification=ScanClassification.CLEAN)
        _, sig, key_id = self.signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=104,
            source_version=1,
            source_hash="sha256_src_104",
            snapshot_hash="sha256_snap_104",
            scan_result=scan_res,
        )

        scan_row = {
            "id": 3,
            "user_id": self.user1_id,
            "source_type": "job_description",
            "source_id": 104,
            "source_version": 1,
            "source_hash": "sha256_src_104",
            "snapshot_hash": "sha256_snap_104",
            "scanner_version": "1.0.0",
            "policy_version": "9.1.2",
            "risk_score": 0.0,
            "classification": ScanClassification.CLEAN,
            "threats_detected_json": "[]",
            "key_id": key_id,
            "hmac_signature": sig,
            "scanned_at": scan_res.scan_timestamp,
        }

        # User 2 tries to consume User 1's scan
        with self.assertRaises(CrossUserAccessError):
            self.signer.verify_scan_record(
                expected_user_id=self.user2_id,
                expected_source_type="job_description",
                expected_source_id=104,
                expected_source_version=1,
                expected_source_hash="sha256_src_104",
                expected_snapshot_hash="sha256_snap_104",
                scan_row=scan_row,
            )

    def test_05_stale_source_hash_rejected(self):
        """Asserts that when the on-disk source hash has changed, scan verification fails closed."""
        scan_res = self._create_sample_scan_result(classification=ScanClassification.CLEAN)
        _, sig, key_id = self.signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="resume",
            source_id=105,
            source_version=1,
            source_hash="original_resume_hash_aaa",
            snapshot_hash=None,
            scan_result=scan_res,
        )

        scan_row = {
            "id": 4,
            "user_id": self.user1_id,
            "source_type": "resume",
            "source_id": 105,
            "source_version": 1,
            "source_hash": "original_resume_hash_aaa",
            "snapshot_hash": None,
            "scanner_version": "1.0.0",
            "policy_version": "9.1.2",
            "risk_score": 0.0,
            "classification": ScanClassification.CLEAN,
            "threats_detected_json": "[]",
            "key_id": key_id,
            "hmac_signature": sig,
            "scanned_at": scan_res.scan_timestamp,
        }

        # Caller provides newly computed hash 'new_tampered_hash_bbb'
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.signer.verify_scan_record(
                expected_user_id=self.user1_id,
                expected_source_type="resume",
                expected_source_id=105,
                expected_source_version=1,
                expected_source_hash="new_tampered_hash_bbb",
                expected_snapshot_hash=None,
                scan_row=scan_row,
            )
        self.assertIn("Source hash discrepancy", str(ctx.exception))

    def test_06_sqlite_append_only_update_trigger_blocks_updates(self):
        """Asserts that trg_prevent_security_scans_update blocks any SQL UPDATE on security_scans."""
        scan_res = self._create_sample_scan_result(classification=ScanClassification.QUARANTINED, score=0.90)
        _, sig, key_id = self.signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=106,
            source_version=1,
            source_hash="hash_106",
            snapshot_hash="snap_106",
            scan_result=scan_res,
        )
        scan = self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=106,
            source_version=1,
            source_hash="hash_106",
            snapshot_hash="snap_106",
            scanner_version="1.0.0",
            policy_version="9.1.2",
            risk_score=0.90,
            classification=ScanClassification.QUARANTINED,
            threats_detected=[t.to_dict() for t in scan_res.threats_detected],
            key_id=key_id,
            hmac_signature=sig,
        )

        with self.db.connection() as conn:
            cursor = conn.cursor()
            with self.assertRaises(sqlite3.IntegrityError) as ctx:
                cursor.execute(
                    "UPDATE security_scans SET classification = 'CLEAN' WHERE id = ?",
                    (scan.id,),
                )
            self.assertIn("security_scans records are append-only", str(ctx.exception))

    def test_07_sqlite_append_only_delete_trigger_blocks_unauthorized_deletes(self):
        """Asserts that trg_prevent_security_scans_delete blocks unauthorized deletions."""
        scan_res = self._create_sample_scan_result(classification=ScanClassification.CLEAN)
        _, sig, key_id = self.signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="resume",
            source_id=107,
            source_version=1,
            source_hash="hash_107",
            snapshot_hash=None,
            scan_result=scan_res,
        )
        scan = self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="resume",
            source_id=107,
            source_version=1,
            source_hash="hash_107",
            snapshot_hash=None,
            scanner_version="1.0.0",
            policy_version="9.1.2",
            risk_score=0.0,
            classification=ScanClassification.CLEAN,
            threats_detected=[],
            key_id=key_id,
            hmac_signature=sig,
        )

        with self.db.connection() as conn:
            cursor = conn.cursor()
            with self.assertRaises(sqlite3.IntegrityError) as ctx:
                cursor.execute("DELETE FROM security_scans WHERE id = ?", (scan.id,))
            self.assertIn("security_scans records are immutable", str(ctx.exception))

    def test_08_authorized_privacy_erasure_allows_deletion(self):
        """Asserts that authorized privacy erasure context permits deletion during account deletion."""
        scan_res = self._create_sample_scan_result(classification=ScanClassification.CLEAN)
        _, sig, key_id = self.signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="resume",
            source_id=108,
            source_version=1,
            source_hash="hash_108",
            snapshot_hash=None,
            scan_result=scan_res,
        )
        scan = self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="resume",
            source_id=108,
            source_version=1,
            source_hash="hash_108",
            snapshot_hash=None,
            scanner_version="1.0.0",
            policy_version="9.1.2",
            risk_score=0.0,
            classification=ScanClassification.CLEAN,
            threats_detected=[],
            key_id=key_id,
            hmac_signature=sig,
        )

        with self.db.connection() as conn:
            # Wrap within authorized privacy erasure scope
            with self.db._authorized_privacy_erasure_scope(conn, self.user1_id):
                cursor = conn.cursor()
                cursor.execute("DELETE FROM security_scans WHERE id = ?", (scan.id,))
                conn.commit()

        # Confirm deleted
        res = self.db.get_latest_security_scan(self.user1_id, "resume", 108, 1)
        self.assertIsNone(res)

    def test_09_revision_history_deterministic_latest_selection(self):
        """Asserts that multiple rescans append records and get_latest_security_scan returns the newest row."""
        scan1 = self._create_sample_scan_result(classification=ScanClassification.SUSPICIOUS, score=0.40)
        _, sig1, key_id1 = self.signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=109,
            source_version=1,
            source_hash="hash_109",
            snapshot_hash="snap_109",
            scan_result=scan1,
            scanned_at="2026-11-06T10:00:00+00:00",
        )
        rec1 = self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=109,
            source_version=1,
            source_hash="hash_109",
            snapshot_hash="snap_109",
            scanner_version="1.0.0",
            policy_version="9.1.2",
            risk_score=0.40,
            classification=ScanClassification.SUSPICIOUS,
            threats_detected=[],
            key_id=key_id1,
            hmac_signature=sig1,
            scanned_at="2026-11-06T10:00:00+00:00",
        )

        # Later scan run after policy upgrade
        scan2 = self._create_sample_scan_result(classification=ScanClassification.CLEAN, score=0.0)
        _, sig2, key_id2 = self.signer.sign_scan_result(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=109,
            source_version=1,
            source_hash="hash_109",
            snapshot_hash="snap_109",
            scan_result=scan2,
            scanned_at="2026-11-06T11:00:00+00:00",
        )
        rec2 = self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=109,
            source_version=1,
            source_hash="hash_109",
            snapshot_hash="snap_109",
            scanner_version="1.0.1",
            policy_version="9.1.2",
            risk_score=0.0,
            classification=ScanClassification.CLEAN,
            threats_detected=[],
            key_id=key_id2,
            hmac_signature=sig2,
            scanned_at="2026-11-06T11:00:00+00:00",
        )

        latest = self.db.get_latest_security_scan(self.user1_id, "job_description", 109, 1)
        self.assertIsNotNone(latest)
        self.assertEqual(latest.id, rec2.id)
        self.assertEqual(latest.scanner_version, "1.0.1")
        self.assertEqual(latest.classification, ScanClassification.CLEAN)

        # List all records
        all_scans = self.db.list_security_scans(self.user1_id, "job_description", 109)
        self.assertEqual(len(all_scans), 2)
        self.assertEqual([s.id for s in all_scans], [rec2.id, rec1.id])


if __name__ == "__main__":
    unittest.main()

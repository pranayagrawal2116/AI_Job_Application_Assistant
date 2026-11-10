"""Comprehensive Cryptographic Regression Tests for Persistent Scan Signing & Key Lifecycle (Phase C.0.5).

Verifies that security scan HMAC signing keys remain durable across restarts and processes,
correctly rotates historical keys, rejects tampering and unknown keys, enforces sticky quarantine,
and restores resume preflight reliability for tailored resume generation.
"""

import os
from pathlib import Path
import subprocess
import sys
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    KeyRevokedError,
    QuarantinedSourceError,
    ScanSignatureMismatchError,
    ScanVerificationKeyUnavailableError,
    SecurityAuthorizationError,
)
from src.security.prompt_injection_detector import PromptInjectionDetector, PromptInjectionScanResult, ScanClassification
from src.security.scan_signer import (
    ScanKeyManager,
    SecurityScanSigner,
)
from src.security.security_preflight import SecurityPreflightManager
from tests.fixtures.synthetic_personas import generate_persona_pdf

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestPersistentScanSigning(unittest.TestCase):
    """Regression test suite for Phase C.0.5 cryptographic scan persistence and recovery."""

    def setUp(self):
        self.test_dir = Path("/tmp") / f"test_c05_{os.getpid()}_{os.urandom(4).hex()}"
        self.test_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.test_dir / "test.db"
        self.key_file = self.test_dir / "scan_signing.key"
        self.storage_dir = self.test_dir / "users"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=str(self.db_path))

        # Setup isolated ScanKeyManager with dedicated key_file
        self.orig_env_key_path = os.environ.get("SECURITY_SCAN_DEV_KEY_PATH")
        os.environ["SECURITY_SCAN_DEV_KEY_PATH"] = str(self.key_file)
        self.key_manager = ScanKeyManager(
            dev_key_path=self.key_file,
            active_key_id="test_dev_v1",
        )
        from src.security.file_security import FileSecurityValidator
        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_dir)
        self.signer = SecurityScanSigner(key_manager=self.key_manager, db_manager=self.db)
        self.preflight = SecurityPreflightManager(
            db_manager=self.db,
            key_manager=self.key_manager,
            file_validator=self.file_validator,
        )

        # Create test candidate
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name, profession_industry) "
                "VALUES ('cand.c05@example.com', 'h', 's', 'Candidate C05', 'accounting_finance')"
            )
            self.user_id = cursor.lastrowid

    def tearDown(self):
        import shutil
        from dashboard.services.dashboard_service import DashboardService
        DashboardService._instance = None
        if self.orig_env_key_path is not None:
            os.environ["SECURITY_SCAN_DEV_KEY_PATH"] = self.orig_env_key_path
        else:
            os.environ.pop("SECURITY_SCAN_DEV_KEY_PATH", None)
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_stable_local_development_key(self):
        """Test 1: Stable local development key across simulated restarts."""
        # Process 1: signs a scan
        scan_res = PromptInjectionDetector().scan("Clean accounting background")
        manifest, sig, kid = self.signer.sign_scan_result(
            user_id=self.user_id,
            source_type="resume",
            source_id=1,
            source_version=1,
            source_hash="hash_111",
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v2",
            source_binary_hash="bin_111",
            source_binary_size_bytes=1000,
            source_binary_format="pdf",
        )
        saved = self.db.save_security_scan(
            user_id=self.user_id,
            source_type="resume",
            source_id=1,
            source_version=1,
            source_hash="hash_111",
            snapshot_hash=None,
            scanner_version=scan_res.engine_version,
            policy_version=scan_res.policy_version,
            risk_score=scan_res.risk_score,
            classification=scan_res.classification,
            threats_detected=[t.to_dict() for t in scan_res.threats_detected],
            key_id=kid,
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            source_binary_hash="bin_111",
            source_binary_size_bytes=1000,
            source_binary_format="pdf",
            manifest_version="v2",
        )

        # Process 2: Simulating restart by creating fresh KeyManager and Signer
        km_restarted = ScanKeyManager(dev_key_path=self.key_file, active_key_id="test_dev_v1")
        signer_restarted = SecurityScanSigner(key_manager=km_restarted, db_manager=self.db)

        # Must verify successfully
        verified = signer_restarted.verify_scan_record(
            expected_user_id=self.user_id,
            expected_source_type="resume",
            expected_source_id=1,
            expected_source_version=1,
            expected_source_hash="hash_111",
            expected_snapshot_hash=None,
            scan_row=saved.to_dict(),
            expected_source_binary_hash="bin_111",
            expected_source_binary_size_bytes=1000,
            expected_source_binary_format="pdf",
        )
        self.assertTrue(verified, "Scan must verify with durable key after simulated restart.")

    def test_02_cross_process_verification(self):
        """Test 2: Separate Python subprocesses share the persistent development key and verify scans."""
        script_a = f"""
import sys
from pathlib import Path
sys.path.insert(0, '{PROJECT_ROOT}')
from src.database.db_manager import DatabaseManager
from src.security.scan_signer import ScanKeyManager, SecurityScanSigner
from src.security.prompt_injection_detector import PromptInjectionDetector

db = DatabaseManager(db_path='{self.db_path}')
km = ScanKeyManager(dev_key_path=Path('{self.key_file}'), active_key_id='test_dev_v1')
signer = SecurityScanSigner(key_manager=km, db_manager=db)

res = PromptInjectionDetector().scan('Candidate verified skills')
manifest, sig, kid = signer.sign_scan_result(
    user_id={self.user_id},
    source_type='resume',
    source_id=2,
    source_version=1,
    source_hash='hash_222',
    snapshot_hash=None,
    scan_result=res,
    manifest_version='v2',
    source_binary_hash='bin_222',
    source_binary_size_bytes=2048,
    source_binary_format='pdf',
)
saved = db.save_security_scan(
    user_id={self.user_id},
    source_type='resume',
    source_id=2,
    source_version=1,
    source_hash='hash_222',
    snapshot_hash=None,
    scanner_version=res.engine_version,
    policy_version=res.policy_version,
    risk_score=res.risk_score,
    classification=res.classification,
    threats_detected=[t.to_dict() for t in res.threats_detected],
    key_id=kid,
    hmac_signature=sig,
    scanned_at=manifest['scanned_at'],
    source_binary_hash='bin_222',
    source_binary_size_bytes=2048,
    source_binary_format='pdf',
    manifest_version='v2',
)
print(saved.id)
"""
        proc_a = subprocess.run([sys.executable, "-c", script_a], capture_output=True, text=True, check=True)
        scan_id = int(proc_a.stdout.strip().splitlines()[-1])

        script_b = f"""
import sys
from pathlib import Path
sys.path.insert(0, '{PROJECT_ROOT}')
from src.database.db_manager import DatabaseManager
from src.security.scan_signer import ScanKeyManager, SecurityScanSigner

db = DatabaseManager(db_path='{self.db_path}')
km = ScanKeyManager(dev_key_path=Path('{self.key_file}'), active_key_id='test_dev_v1')
signer = SecurityScanSigner(key_manager=km, db_manager=db)

scan = db.get_security_scan_by_id({scan_id})
signer.verify_scan_record(
    expected_user_id={self.user_id},
    expected_source_type='resume',
    expected_source_id=2,
    expected_source_version=1,
    expected_source_hash='hash_222',
    expected_snapshot_hash=None,
    scan_row=scan.to_dict(),
    expected_source_binary_hash='bin_222',
    expected_source_binary_size_bytes=2048,
    expected_source_binary_format='pdf',
)
print('VERIFIED_OK')
"""
        proc_b = subprocess.run([sys.executable, "-c", script_b], capture_output=True, text=True, check=True)
        self.assertIn("VERIFIED_OK", proc_b.stdout, "Subprocess B must verify scan signed by Subprocess A.")

    def test_03_different_key_rejection(self):
        """Test 3: Changing the key intentionally fails verification with SIGNATURE_MISMATCH."""
        scan_res = PromptInjectionDetector().scan("Candidate text")
        manifest, sig, kid = self.signer.sign_scan_result(
            user_id=self.user_id,
            source_type="resume",
            source_id=3,
            source_version=1,
            source_hash="hash_333",
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v2",
            source_binary_hash="bin_333",
            source_binary_size_bytes=3000,
            source_binary_format="pdf",
        )
        saved = self.db.save_security_scan(
            user_id=self.user_id,
            source_type="resume",
            source_id=3,
            source_version=1,
            source_hash="hash_333",
            snapshot_hash=None,
            scanner_version=scan_res.engine_version,
            policy_version=scan_res.policy_version,
            risk_score=scan_res.risk_score,
            classification=scan_res.classification,
            threats_detected=[],
            key_id=kid,
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            source_binary_hash="bin_333",
            source_binary_size_bytes=3000,
            source_binary_format="pdf",
            manifest_version="v2",
        )

        # Create signer with a completely different secret for the same key ID
        different_key = os.urandom(32)
        km_diff = ScanKeyManager(signing_key=different_key, active_key_id=kid)
        signer_diff = SecurityScanSigner(key_manager=km_diff, db_manager=self.db)

        with self.assertRaises(ScanSignatureMismatchError):
            signer_diff.verify_scan_record(
                expected_user_id=self.user_id,
                expected_source_type="resume",
                expected_source_id=3,
                expected_source_version=1,
                expected_source_hash="hash_333",
                expected_snapshot_hash=None,
                scan_row=saved.to_dict(),
                expected_source_binary_hash="bin_333",
                expected_source_binary_size_bytes=3000,
                expected_source_binary_format="pdf",
            )

    def test_04_historical_rotation_key(self):
        """Test 4: Historical rotation keys verify older scans while new scans use active key."""
        old_secret = os.urandom(32)
        km_old = ScanKeyManager(signing_key=old_secret, active_key_id="rot_key_v1")
        signer_old = SecurityScanSigner(key_manager=km_old, db_manager=self.db)

        res = PromptInjectionDetector().scan("Historical document")
        manifest, sig, kid = signer_old.sign_scan_result(
            user_id=self.user_id,
            source_type="resume",
            source_id=4,
            source_version=1,
            source_hash="hash_444",
            snapshot_hash=None,
            scan_result=res,
            manifest_version="v2",
            source_binary_hash="bin_444",
            source_binary_size_bytes=4000,
            source_binary_format="pdf",
        )
        saved = self.db.save_security_scan(
            user_id=self.user_id,
            source_type="resume",
            source_id=4,
            source_version=1,
            source_hash="hash_444",
            snapshot_hash=None,
            scanner_version=res.engine_version,
            policy_version=res.policy_version,
            risk_score=res.risk_score,
            classification=res.classification,
            threats_detected=[],
            key_id="rot_key_v1",
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            source_binary_hash="bin_444",
            source_binary_size_bytes=4000,
            source_binary_format="pdf",
            manifest_version="v2",
        )

        # Now active key rotates to rot_key_v2, with rot_key_v1 in rotation keys
        new_secret = os.urandom(32)
        km_new = ScanKeyManager(
            signing_key=new_secret,
            active_key_id="rot_key_v2",
            rotation_keys={"rot_key_v1": old_secret},
        )
        signer_new = SecurityScanSigner(key_manager=km_new, db_manager=self.db)

        # Active key is v2
        self.assertEqual(km_new.active_key_id, "rot_key_v2")

        # Historical v1 scan must verify successfully via rotation key
        verified = signer_new.verify_scan_record(
            expected_user_id=self.user_id,
            expected_source_type="resume",
            expected_source_id=4,
            expected_source_version=1,
            expected_source_hash="hash_444",
            expected_snapshot_hash=None,
            scan_row=saved.to_dict(),
            expected_source_binary_hash="bin_444",
            expected_source_binary_size_bytes=4000,
            expected_source_binary_format="pdf",
        )
        self.assertTrue(verified, "Historical scan must verify using configured rotation key.")

    def test_05_revoked_key(self):
        """Test 5: Explicitly revoked keys reject verification immediately."""
        key = os.urandom(32)
        km = ScanKeyManager(signing_key=key, active_key_id="revocable_key", db_manager=self.db)
        signer = SecurityScanSigner(key_manager=km, db_manager=self.db)

        res = PromptInjectionDetector().scan("Clean text")
        manifest, sig, kid = signer.sign_scan_result(
            user_id=self.user_id,
            source_type="resume",
            source_id=5,
            source_version=1,
            source_hash="hash_555",
            snapshot_hash=None,
            scan_result=res,
            manifest_version="v2",
            source_binary_hash="bin_555",
            source_binary_size_bytes=5000,
            source_binary_format="pdf",
        )
        saved = self.db.save_security_scan(
            user_id=self.user_id,
            source_type="resume",
            source_id=5,
            source_version=1,
            source_hash="hash_555",
            snapshot_hash=None,
            scanner_version=res.engine_version,
            policy_version=res.policy_version,
            risk_score=res.risk_score,
            classification=res.classification,
            threats_detected=[],
            key_id="revocable_key",
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            source_binary_hash="bin_555",
            source_binary_size_bytes=5000,
            source_binary_format="pdf",
            manifest_version="v2",
        )

        # Revoke key
        km.revoke_key("revocable_key", reason="Test revocation")

        with self.assertRaises(KeyRevokedError):
            signer.verify_scan_record(
                expected_user_id=self.user_id,
                expected_source_type="resume",
                expected_source_id=5,
                expected_source_version=1,
                expected_source_hash="hash_555",
                expected_snapshot_hash=None,
                scan_row=saved.to_dict(),
                expected_source_binary_hash="bin_555",
                expected_source_binary_size_bytes=5000,
                expected_source_binary_format="pdf",
            )

    def test_06_tampered_scan_record(self):
        """Test 6: Tampering with any signed field raises ScanSignatureMismatchError."""
        scan_res = PromptInjectionDetector().scan("Candidate text")
        manifest, sig, kid = self.signer.sign_scan_result(
            user_id=self.user_id,
            source_type="resume",
            source_id=6,
            source_version=1,
            source_hash="hash_666",
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v2",
            source_binary_hash="bin_666",
            source_binary_size_bytes=6000,
            source_binary_format="pdf",
        )
        saved = self.db.save_security_scan(
            user_id=self.user_id,
            source_type="resume",
            source_id=6,
            source_version=1,
            source_hash="hash_666",
            snapshot_hash=None,
            scanner_version=scan_res.engine_version,
            policy_version=scan_res.policy_version,
            risk_score=scan_res.risk_score,
            classification=scan_res.classification,
            threats_detected=[],
            key_id=kid,
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            source_binary_hash="bin_666",
            source_binary_size_bytes=6000,
            source_binary_format="pdf",
            manifest_version="v2",
        )

        tampered_dict = saved.to_dict()
        tampered_dict["classification"] = "SUSPICIOUS"  # Alter field

        with self.assertRaises(ScanSignatureMismatchError):
            self.signer.verify_scan_record(
                expected_user_id=self.user_id,
                expected_source_type="resume",
                expected_source_id=6,
                expected_source_version=1,
                expected_source_hash="hash_666",
                expected_snapshot_hash=None,
                scan_row=tampered_dict,
                expected_source_binary_hash="bin_666",
                expected_source_binary_size_bytes=6000,
                expected_source_binary_format="pdf",
            )

    def test_07_sqlite_round_trip(self):
        """Test 7: SQLite round-trip preserves v1 and v2 canonical manifest bytes and signatures."""
        res = PromptInjectionDetector().scan("Round trip text")

        # Test v1
        m1, s1, k1 = self.signer.sign_scan_result(
            user_id=self.user_id,
            source_type="job_description",
            source_id=7,
            source_version=1,
            source_hash="hash_777_v1",
            snapshot_hash=None,
            scan_result=res,
            manifest_version="v1",
        )
        saved_v1 = self.db.save_security_scan(
            user_id=self.user_id,
            source_type="job_description",
            source_id=7,
            source_version=1,
            source_hash="hash_777_v1",
            snapshot_hash=None,
            scanner_version=res.engine_version,
            policy_version=res.policy_version,
            risk_score=res.risk_score,
            classification=res.classification,
            threats_detected=[],
            key_id=k1,
            hmac_signature=s1,
            scanned_at=m1["scanned_at"],
            manifest_version="v1",
        )
        retrieved_v1 = self.db.get_security_scan_by_id(saved_v1.id)
        self.assertIsNotNone(retrieved_v1)
        self.assertEqual(retrieved_v1.user_id, self.user_id)
        self.assertTrue(
            self.signer.verify_scan_record(
                expected_user_id=self.user_id,
                expected_source_type="job_description",
                expected_source_id=7,
                expected_source_version=1,
                expected_source_hash="hash_777_v1",
                expected_snapshot_hash=None,
                scan_row=retrieved_v1.to_dict(),
            )
        )

        # Test v2
        m2, s2, k2 = self.signer.sign_scan_result(
            user_id=self.user_id,
            source_type="resume",
            source_id=7,
            source_version=1,
            source_hash="hash_777_v2",
            snapshot_hash=None,
            scan_result=res,
            manifest_version="v2",
            source_binary_hash="bin_777",
            source_binary_size_bytes=7770,
            source_binary_format="pdf",
        )
        saved_v2 = self.db.save_security_scan(
            user_id=self.user_id,
            source_type="resume",
            source_id=7,
            source_version=1,
            source_hash="hash_777_v2",
            snapshot_hash=None,
            scanner_version=res.engine_version,
            policy_version=res.policy_version,
            risk_score=res.risk_score,
            classification=res.classification,
            threats_detected=[],
            key_id=k2,
            hmac_signature=s2,
            scanned_at=m2["scanned_at"],
            source_binary_hash="bin_777",
            source_binary_size_bytes=7770,
            source_binary_format="pdf",
            manifest_version="v2",
        )
        retrieved_v2 = self.db.get_security_scan_by_id(saved_v2.id)
        self.assertIsNotNone(retrieved_v2)
        self.assertEqual(retrieved_v2.user_id, self.user_id)
        self.assertTrue(
            self.signer.verify_scan_record(
                expected_user_id=self.user_id,
                expected_source_type="resume",
                expected_source_id=7,
                expected_source_version=1,
                expected_source_hash="hash_777_v2",
                expected_snapshot_hash=None,
                scan_row=retrieved_v2.to_dict(),
                expected_source_binary_hash="bin_777",
                expected_source_binary_size_bytes=7770,
                expected_source_binary_format="pdf",
            )
        )

    def test_08_invalid_key_id(self):
        """Test 8: An unknown historical key ID raises ScanVerificationKeyUnavailableError."""
        row = {
            "id": 888,
            "user_id": self.user_id,
            "source_type": "resume",
            "source_id": 8,
            "source_version": 1,
            "source_hash": "hash_888",
            "snapshot_hash": None,
            "scanner_version": "1.0.0",
            "policy_version": "9.1.2",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "key_id": "lost_historical_key_999",
            "hmac_signature": "0" * 64,
            "manifest_version": "v2",
            "source_binary_hash": "bin_888",
            "source_binary_size_bytes": 8000,
            "source_binary_format": "pdf",
            "scanned_at": "2026-11-10T12:00:00+00:00",
        }
        with self.assertRaises(ScanVerificationKeyUnavailableError) as ctx:
            self.signer.verify_scan_record(
                expected_user_id=self.user_id,
                expected_source_type="resume",
                expected_source_id=8,
                expected_source_version=1,
                expected_source_hash="hash_888",
                expected_snapshot_hash=None,
                scan_row=row,
                expected_source_binary_hash="bin_888",
                expected_source_binary_size_bytes=8000,
                expected_source_binary_format="pdf",
            )
        self.assertEqual(ctx.exception.failure_category, "VERIFICATION_KEY_UNAVAILABLE")

    def test_09_resume_replacement_and_scan_recovery(self):
        """Test 9: Authorized recovery re-establishes a verified scan under current key while preserving original record."""
        # 1. Upload valid resume binary
        pdf_bytes = generate_persona_pdf("acca_finance_professional")
        res_rec = self.db.upload_user_resume(
            user_id=self.user_id,
            file_bytes=pdf_bytes,
            original_filename="pranjali_resume.pdf",
            user_base_dir=self.storage_dir,
        )
        resume_id = res_rec["id"]

        # 2. Simulate historical scan created with an older key that is now lost
        lost_secret = os.urandom(32)
        km_lost = ScanKeyManager(signing_key=lost_secret, active_key_id="lost_old_key")
        signer_lost = SecurityScanSigner(key_manager=km_lost, db_manager=self.db)

        scan_res = PromptInjectionDetector().scan("Authentic ACCA resume")
        m, sig, kid = signer_lost.sign_scan_result(
            user_id=self.user_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scan_result=scan_res,
            manifest_version="v2",
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=res_rec["file_size_bytes"],
            source_binary_format="pdf",
        )
        old_scan = self.db.save_security_scan(
            user_id=self.user_id,
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
            key_id="lost_old_key",
            hmac_signature=sig,
            scanned_at=m["scanned_at"],
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=res_rec["file_size_bytes"],
            source_binary_format="pdf",
            manifest_version="v2",
        )
        old_scan_id = old_scan.id

        # 3. Regular preflight fails with ScanVerificationKeyUnavailableError
        with self.assertRaises(ScanVerificationKeyUnavailableError):
            self.preflight.check_resume_security(user_id=self.user_id, resume_id=resume_id, version_num=1)

        # 4. Authorized recovery action
        recovery_result = self.preflight.recover_unverifiable_resume_scan(
            user_id=self.user_id,
            resume_id=resume_id,
            version_num=1,
            recovery_reason="Test authorized recovery",
        )
        self.assertTrue(recovery_result.is_allowed)

        # 5. Confirm original scan record remains untouched in SQLite (Test 11 - Tamper preservation)
        original_scan = self.db.get_security_scan_by_id(old_scan_id)
        self.assertIsNotNone(original_scan, "Original scan record must never be deleted.")
        self.assertEqual(original_scan.user_id, self.user_id)
        self.assertEqual(original_scan.key_id, "lost_old_key")
        self.assertEqual(original_scan.hmac_signature, sig)

        # 6. Latest scan is new and verified
        latest_scan = self.db.get_latest_security_scan(user_id=self.user_id, source_type="resume", source_id=resume_id, source_version=1)
        self.assertNotEqual(latest_scan.id, old_scan_id, "A new scan row must be created.")
        self.assertEqual(latest_scan.key_id, self.key_manager.active_key_id)

        # 7. Check that standard preflight now passes cleanly
        preflight_now = self.preflight.check_resume_security(user_id=self.user_id, resume_id=resume_id, version_num=1)
        self.assertTrue(preflight_now.is_allowed)

    def test_10_tailored_resume_integration(self):
        """Test 10: Tailor resume endpoint succeeds after establishing verified scan with durable key."""
        from dashboard.services.dashboard_service import DashboardService

        DashboardService._instance = None
        service = DashboardService.get_instance(db_manager=self.db, storage_base_dir=self.storage_dir)

        # Upload resume
        pdf_bytes = generate_persona_pdf("acca_finance_professional")
        res_rec = self.db.upload_user_resume(
            user_id=self.user_id,
            file_bytes=pdf_bytes,
            original_filename="candidate_resume.pdf",
            user_base_dir=self.storage_dir,
            set_as_primary=True,
        )
        resume_id = res_rec["id"]

        # Preflight/recover to ensure scan exists with current key
        self.preflight.recover_unverifiable_resume_scan(user_id=self.user_id, resume_id=resume_id, version_num=1)

        # Ingest Job Description
        jd = self.db.save_job_description_snapshot(
            user_id=self.user_id,
            company_name="Acme Finance Ltd",
            job_title="Tax Analyst",
            raw_content="Looking for a Tax Analyst with UK tax, direct tax, and financial reporting skills.",
            source_type="pasted",
        )

        saved_app = self.db.create_user_application(
            user_id=self.user_id,
            company_name="Acme Finance Ltd",
            job_title="Tax Analyst",
            job_description_id=jd.id,
            resume_id=resume_id,
        )
        self.assertIsNotNone(saved_app)

        # Execute tailoring via service
        candidate_profile = self.db.get_user_candidate_profile(self.user_id) or {}
        tailored = service.generate_tailored_resume(
            user_id=self.user_id,
            candidate_profile=candidate_profile,
            resume_data=res_rec,
            job_description=jd.to_dict(),
            resume_id=resume_id,
            resume_version_num=1,
        )
        self.assertIsNotNone(tailored)
        self.assertIn("Acme Finance Ltd", str(tailored))

    def test_11_tamper_preservation(self):
        """Test 11: Tampered scans cannot be bypassed via recovery (fail-closed)."""
        pdf_bytes = generate_persona_pdf("acca_finance_professional")
        res_rec = self.db.upload_user_resume(
            user_id=self.user_id,
            file_bytes=pdf_bytes,
            original_filename="test_tamper.pdf",
            user_base_dir=self.storage_dir,
        )
        resume_id = res_rec["id"]

        # Create scan with active key
        res = PromptInjectionDetector().scan("Candidate text")
        manifest, sig, kid = self.signer.sign_scan_result(
            user_id=self.user_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scan_result=res,
            manifest_version="v2",
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=res_rec["file_size_bytes"],
            source_binary_format="pdf",
        )
        # Save scan with corrupted signature to simulate stored record tampering
        saved = self.db.save_security_scan(
            user_id=self.user_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scanner_version=res.engine_version,
            policy_version=res.policy_version,
            risk_score=res.risk_score,
            classification=res.classification,
            threats_detected=[],
            key_id=kid,
            hmac_signature="f" * 64,
            scanned_at=manifest["scanned_at"],
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=res_rec["file_size_bytes"],
            source_binary_format="pdf",
            manifest_version="v2",
        )
        self.assertIsNotNone(saved)

        # Because the key IS available and signature mismatch occurred (tampering), recovery must be REFUSED
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.recover_unverifiable_resume_scan(
                user_id=self.user_id,
                resume_id=resume_id,
                version_num=1,
            )
        self.assertIn("Signature mismatch detected", str(ctx.exception))

    def test_12_quarantine_remains_enforced(self):
        """Test 12: Sticky quarantine cannot be bypassed by key recovery."""
        pdf_bytes = generate_persona_pdf("acca_finance_professional")
        res_rec = self.db.upload_user_resume(
            user_id=self.user_id,
            file_bytes=pdf_bytes,
            original_filename="quarantined_resume.pdf",
            user_base_dir=self.storage_dir,
        )
        resume_id = res_rec["id"]

        # Insert historical scan marked as QUARANTINED with lost key
        m, sig, kid = self.signer.sign_scan_result(
            user_id=self.user_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scan_result=PromptInjectionScanResult(
                engine_version="1.0.0",
                policy_version="9.1.2",
                risk_score=1.0,
                classification=ScanClassification.QUARANTINED,
                threats_detected=[],
                threat_count=1,
                original_text_length=100,
                scan_timestamp="2026-11-10T12:00:00+00:00",
            ),
            manifest_version="v2",
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=res_rec["file_size_bytes"],
            source_binary_format="pdf",
        )
        self.db.save_security_scan(
            user_id=self.user_id,
            source_type="resume",
            source_id=resume_id,
            source_version=1,
            source_hash=res_rec["file_hash"],
            snapshot_hash=None,
            scanner_version="1.0.0",
            policy_version="9.1.2",
            risk_score=1.0,
            classification=ScanClassification.QUARANTINED,
            threats_detected=[],
            key_id="lost_key_q",
            hmac_signature=sig,
            scanned_at=m["scanned_at"],
            source_binary_hash=res_rec["file_hash"],
            source_binary_size_bytes=res_rec["file_size_bytes"],
            source_binary_format="pdf",
            manifest_version="v2",
        )

        # Recovery on a quarantined document must preserve quarantine status
        res = self.preflight.recover_unverifiable_resume_scan(
            user_id=self.user_id,
            resume_id=resume_id,
            version_num=1,
        )
        self.assertEqual(res.classification, ScanClassification.QUARANTINED, "Quarantine must remain sticky across recovery.")

        # Document generation must be blocked for quarantined document
        with self.assertRaises(QuarantinedSourceError):
            self.preflight.check_resume_security(
                user_id=self.user_id,
                resume_id=resume_id,
                version_num=1,
                target_action="document_generation",
            )

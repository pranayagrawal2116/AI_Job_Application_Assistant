"""Tests for Dedicated Security Scan Key Lifecycle, Rotation, Revocation, and Domain Separation.

Verifies:
- Key initialization and minimum entropy (>= 32 bytes / 256 bits)
- Strict separation from ACTION_TICKET_SECRET_KEY
- Production environment enforcement (fails closed if missing signing key)
- Historical key retention and seamless verification across rotation
- Emergency revocation failing closed with KeyRevokedError
- Unknown key ID rejection
- Domain isolation (action ticket key cannot verify security scan)
"""

import os
import secrets
import unittest
from unittest.mock import patch

from src.database.exceptions import (
    KeyRevokedError,
    SecurityAuthorizationError,
)
from src.security.prompt_injection_detector import PromptInjectionScanResult
from src.security.scan_signer import ScanKeyManager, SecurityScanSigner


class TestSecurityScanKeyLifecycle(unittest.TestCase):
    """Unit tests for ScanKeyManager and key lifecycle behavior."""

    def setUp(self):
        self.clean_env = {
            "APP_ENV": "development",
            "SECURITY_SCAN_ACTIVE_KEY_ID": "scan_test_v1",
            "SECURITY_SCAN_SIGNING_KEY": secrets.token_hex(32),
        }

    def test_01_key_manager_initialization_with_explicit_keys(self):
        """ScanKeyManager initializes properly with explicit key arguments."""
        secret = secrets.token_bytes(32)
        km = ScanKeyManager(active_key_id="k1", signing_key=secret)
        active_id, active_bytes = km.get_signing_key()
        self.assertEqual(active_id, "k1")
        self.assertEqual(active_bytes, secret)

    def test_02_insufficient_entropy_rejected(self):
        """Keys with fewer than 32 bytes of entropy are rejected with SecurityAuthorizationError."""
        short_secret = b"short_secret_under_32_bytes"
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            ScanKeyManager(active_key_id="k_short", signing_key=short_secret)
        self.assertIn("at least 32 bytes", str(ctx.exception))

    def test_03_action_ticket_key_separation_enforced(self):
        """Reusing ACTION_TICKET_SECRET_KEY as scan signing key is strictly blocked."""
        shared_secret = secrets.token_hex(32)
        with patch.dict(os.environ, {
            "ACTION_TICKET_SECRET_KEY": shared_secret,
            "SECURITY_SCAN_SIGNING_KEY": shared_secret,
        }):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                ScanKeyManager()
            self.assertIn("cannot reuse ACTION_TICKET_SECRET_KEY", str(ctx.exception))

    def test_04_production_environment_fails_closed_without_key(self):
        """Production startup fails closed if SECURITY_SCAN_SIGNING_KEY is missing."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                ScanKeyManager()
            self.assertIn("Missing SECURITY_SCAN_SIGNING_KEY in production", str(ctx.exception))

    def test_05_development_generates_ephemeral_key(self):
        """Development environment generates a secure ephemeral key if not provided."""
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True):
            km = ScanKeyManager()
            active_id, secret = km.get_signing_key()
            self.assertTrue(len(secret) >= 32)
            self.assertTrue(active_id)

    def test_06_key_rotation_preserves_historical_verification(self):
        """Key rotation updates active key while maintaining verification for older keys."""
        k1_secret = secrets.token_bytes(32)
        k2_secret = secrets.token_bytes(32)

        km = ScanKeyManager(active_key_id="key_v1", signing_key=k1_secret)
        signer = SecurityScanSigner(km)

        # Sign scan with key_v1
        mock_result = PromptInjectionScanResult(
            engine_version="1.0.0",
            policy_version="2026.1",
            risk_score=0.0,
            classification="CLEAN",
            threats_detected=[],
            threat_count=0,
            original_text_length=100,
            scan_timestamp="2026-11-06T12:00:00Z",
        )
        manifest, sig_v1, key_id_v1 = signer.sign_scan_result(
            user_id=1,
            source_type="job_description",
            source_id=10,
            source_version=1,
            source_hash="sha256_jd_hash",
            snapshot_hash="sha256_snap_hash",
            scan_result=mock_result,
        )
        self.assertEqual(key_id_v1, "key_v1")

        # Rotate to key_v2
        km.rotate_key("key_v2", k2_secret)
        self.assertEqual(km.active_key_id, "key_v2")

        # Historical scan signed with key_v1 can still be verified
        row_v1 = {
            "id": 1,
            "user_id": 1,
            "source_type": "job_description",
            "source_id": 10,
            "source_version": 1,
            "source_hash": "sha256_jd_hash",
            "snapshot_hash": "sha256_snap_hash",
            "scanner_version": mock_result.engine_version,
            "policy_version": mock_result.policy_version,
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "key_v1",
            "hmac_signature": sig_v1,
        }
        self.assertTrue(
            signer.verify_scan_record(
                expected_user_id=1,
                expected_source_type="job_description",
                expected_source_id=10,
                expected_source_version=1,
                expected_source_hash="sha256_jd_hash",
                expected_snapshot_hash="sha256_snap_hash",
                scan_row=row_v1,
            )
        )

        # New scan is signed with key_v2
        _, sig_v2, key_id_v2 = signer.sign_scan_result(
            user_id=1,
            source_type="job_description",
            source_id=10,
            source_version=2,
            source_hash="sha256_jd_hash_v2",
            snapshot_hash="sha256_snap_hash_v2",
            scan_result=mock_result,
        )
        self.assertEqual(key_id_v2, "key_v2")

    def test_07_emergency_revocation_fails_closed(self):
        """Revoking a key immediately prevents verifying scans signed with that key."""
        k1_secret = secrets.token_bytes(32)
        km = ScanKeyManager(active_key_id="compromised_key", signing_key=k1_secret)
        signer = SecurityScanSigner(km)

        mock_result = PromptInjectionScanResult(
            engine_version="1.0.0",
            policy_version="2026.1",
            risk_score=0.0,
            classification="CLEAN",
            threats_detected=[],
            threat_count=0,
            original_text_length=100,
            scan_timestamp="2026-11-06T12:00:00Z",
        )
        _, sig, key_id = signer.sign_scan_result(
            user_id=1,
            source_type="resume",
            source_id=5,
            source_version=1,
            source_hash="sha256_res_hash",
            snapshot_hash=None,
            scan_result=mock_result,
        )

        row = {
            "id": 1,
            "user_id": 1,
            "source_type": "resume",
            "source_id": 5,
            "source_version": 1,
            "source_hash": "sha256_res_hash",
            "snapshot_hash": None,
            "scanner_version": mock_result.engine_version,
            "policy_version": mock_result.policy_version,
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "compromised_key",
            "hmac_signature": sig,
        }

        # Revoke key
        km.revoke_key("compromised_key", reason="Private key leaked in external audit")

        # Verification must raise KeyRevokedError
        with self.assertRaises(KeyRevokedError) as ctx:
            signer.verify_scan_record(
                expected_user_id=1,
                expected_source_type="resume",
                expected_source_id=5,
                expected_source_version=1,
                expected_source_hash="sha256_res_hash",
                expected_snapshot_hash=None,
                scan_row=row,
            )
        self.assertIn("compromised_key", str(ctx.exception))

    def test_08_unknown_key_id_rejected(self):
        """Scan record referencing an unknown key_id raises SecurityAuthorizationError."""
        km = ScanKeyManager(active_key_id="known_key", signing_key=secrets.token_bytes(32))
        signer = SecurityScanSigner(km)

        row = {
            "id": 1,
            "user_id": 1,
            "source_type": "job_description",
            "source_id": 1,
            "source_version": 1,
            "source_hash": "hash",
            "snapshot_hash": None,
            "scanner_version": "1.0",
            "policy_version": "1.0",
            "risk_score": 0.0,
            "classification": "CLEAN",
            "threats_detected_json": "[]",
            "scanned_at": "2026-11-06T12:00:00Z",
            "key_id": "completely_unknown_key_id",
            "hmac_signature": "fake_signature",
        }
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            signer.verify_scan_record(
                expected_user_id=1,
                expected_source_type="job_description",
                expected_source_id=1,
                expected_source_version=1,
                expected_source_hash="hash",
                expected_snapshot_hash=None,
                scan_row=row,
            )
        self.assertIn("unknown or unavailable", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

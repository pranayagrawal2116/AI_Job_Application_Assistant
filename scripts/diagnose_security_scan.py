#!/usr/bin/env python3
"""Diagnostic Tool for Security Scans in JobFlow AI.

Inspects a persisted security scan record in read-only mode, reconstructs its
canonical RFC 8785 manifest, checks key availability, and validates cryptographic
integrity without disclosing secrets or modifying database records.
"""

import argparse
import hashlib
from pathlib import Path
import sqlite3
import sys
from typing import Any, Dict, Optional

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.database.db_manager import get_default_db_path
from src.database.exceptions import (
    KeyRevokedError,
    ScanVerificationKeyUnavailableError,
    SecurityAuthorizationError,
    SecurityScanVerificationError,
)
from src.security.scan_signer import SecurityScanSigner


def redact_path(path_str: Optional[str]) -> str:
    """Redacts sensitive absolute paths, leaving only the filename or safe tail."""
    if not path_str:
        return "N/A"
    return Path(path_str).name


def diagnose_scan(scan_id: int, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Inspects and diagnoses a security scan record in read-only mode."""
    target_db = Path(db_path) if db_path else get_default_db_path()
    if not target_db.exists():
        return {
            "status": "FAIL",
            "failure_category": "DATABASE_NOT_FOUND",
            "message": f"Database file does not exist at {redact_path(str(target_db))}",
        }

    # Connect strictly in read-only mode
    uri = f"file:{target_db.resolve()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
    except Exception as e:
        return {
            "status": "FAIL",
            "failure_category": "CONNECTION_ERROR",
            "message": f"Failed opening database in read-only mode: {e}",
        }

    try:
        cursor.execute("SELECT * FROM security_scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return {
                "status": "FAIL",
                "failure_category": "SCAN_RECORD_NOT_FOUND",
                "scan_id": scan_id,
                "message": f"Security scan #{scan_id} not found in database.",
            }

        scan_dict = dict(row)
        user_id = scan_dict.get("user_id")
        source_type = scan_dict.get("source_type")
        source_id = scan_dict.get("source_id")
        source_version = scan_dict.get("source_version") or 1
        key_id = scan_dict.get("key_id") or "UNKNOWN"
        manifest_ver = scan_dict.get("manifest_version") or "v1"
        classification = scan_dict.get("classification") or "UNKNOWN"

        # Check binary metadata if resume or uploaded JD
        expected_bin_hash = scan_dict.get("source_binary_hash")
        expected_bin_size = scan_dict.get("source_binary_size_bytes")
        expected_bin_format = scan_dict.get("source_binary_format")
        source_file_found = False
        physical_hash_matches = None

        if source_type == "resume":
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (source_id,))
            res_row = cursor.fetchone()
            if res_row:
                res_dict = dict(res_row)
                storage_fn = res_dict.get("storage_filename")
                if storage_fn and user_id:
                    candidate_file = PROJECT_ROOT / "data" / "users" / str(user_id) / "resumes" / storage_fn
                    if candidate_file.exists():
                        source_file_found = True
                        data = candidate_file.read_bytes()
                        actual_bin_hash = hashlib.sha256(data).hexdigest()
                        physical_hash_matches = (actual_bin_hash == scan_dict.get("source_hash"))
        elif source_type == "job_description":
            cursor.execute("SELECT * FROM job_descriptions WHERE id = ?", (source_id,))
            jd_row = cursor.fetchone()
            if jd_row:
                jd_dict = dict(jd_row)
                storage_fn = jd_dict.get("storage_filename")
                if storage_fn and user_id:
                    candidate_file = PROJECT_ROOT / "data" / "users" / str(user_id) / "job_descriptions" / storage_fn
                    if candidate_file.exists():
                        source_file_found = True
                        data = candidate_file.read_bytes()
                        actual_bin_hash = hashlib.sha256(data).hexdigest()
                        physical_hash_matches = (actual_bin_hash == scan_dict.get("source_hash"))

        # Instantiate signer and check key availability
        signer = SecurityScanSigner()
        active_key_id = signer.key_manager.active_key_id
        is_key_active = (key_id == active_key_id)
        is_key_revoked = False
        is_key_available = False

        try:
            _ = signer.key_manager.get_verification_key(key_id)
            is_key_available = True
        except KeyRevokedError:
            is_key_revoked = True
        except ScanVerificationKeyUnavailableError:
            is_key_available = False
        except SecurityAuthorizationError:
            is_key_available = False

        # Attempt verification
        verification_passed = False
        failure_category: Optional[str] = None
        failure_reason: Optional[str] = None

        try:
            signer.verify_scan_record(
                expected_user_id=user_id,
                expected_source_type=source_type,
                expected_source_id=source_id,
                expected_source_version=source_version,
                expected_source_hash=scan_dict.get("source_hash"),
                expected_snapshot_hash=scan_dict.get("snapshot_hash"),
                scan_row=scan_dict,
                expected_source_binary_hash=expected_bin_hash if manifest_ver == "v2" else None,
                expected_source_binary_size_bytes=expected_bin_size if manifest_ver == "v2" else None,
                expected_source_binary_format=expected_bin_format if manifest_ver == "v2" else None,
            )
            verification_passed = True
        except SecurityScanVerificationError as sse:
            failure_category = sse.failure_category
            failure_reason = str(sse)
        except KeyRevokedError as kre:
            failure_category = "KEY_REVOKED"
            failure_reason = str(kre)
        except Exception as ex:
            failure_category = "INTEGRITY_VERIFICATION_FAILED"
            failure_reason = str(ex)

        # Formulate safe recovery action
        recovery_action: str
        if verification_passed:
            recovery_action = "None required. Record verified successfully."
        elif failure_category == "VERIFICATION_KEY_UNAVAILABLE":
            if source_file_found and physical_hash_matches:
                recovery_action = (
                    "Historical signing key is unavailable. Original document binary is intact and verified. "
                    "Execute authorized scan recovery (or re-upload resume) to establish a fresh verified scan with the active signing key."
                )
            else:
                recovery_action = (
                    "Historical signing key is unavailable and physical binary could not be verified on disk. "
                    "The candidate must re-upload their resume to establish a verified scan."
                )
        elif failure_category == "SIGNATURE_MISMATCH":
            recovery_action = (
                "CRITICAL: HMAC signature does not match canonical manifest with available key. "
                "Document generation is strictly blocked. Tampered record must be investigated."
            )
        elif failure_category == "KEY_REVOKED":
            recovery_action = (
                "Key was explicitly revoked. Candidate must re-authorize or re-upload document under a valid key."
            )
        else:
            recovery_action = "Inspect source document and re-upload to generate a fresh verified scan."

        return {
            "status": "PASS" if verification_passed else "FAIL",
            "scan_id": scan_id,
            "source_type": source_type,
            "source_id": source_id,
            "source_version": source_version,
            "key_id": key_id,
            "manifest_version": manifest_ver,
            "classification": classification,
            "is_key_available": is_key_available,
            "is_key_active": is_key_active,
            "is_key_revoked": is_key_revoked,
            "source_file_present_on_disk": source_file_found,
            "physical_binary_hash_verified": physical_hash_matches,
            "verification_result": "VERIFIED" if verification_passed else "FAILED",
            "failure_category": failure_category,
            "failure_reason": failure_reason,
            "recommended_recovery_action": recovery_action,
        }
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Diagnostic tool for JobFlow AI security scan records.")
    parser.add_argument("--scan-id", type=int, required=True, help="Security scan record ID to inspect.")
    parser.add_argument("--db-path", type=str, default=None, help="Optional explicit path to SQLite database.")
    args = parser.parse_args()

    result = diagnose_scan(scan_id=args.scan_id, db_path=args.db_path)

    print("\n" + "=" * 70)
    print(f" SECURITY SCAN DIAGNOSTIC REPORT: SCAN #{args.scan_id}")
    print("=" * 70)
    print(f" Status:                        {result.get('status')}")
    print(f" Scan ID:                       {result.get('scan_id')}")
    print(f" Source Type:                   {result.get('source_type')}")
    print(f" Source ID:                     {result.get('source_id')}")
    print(f" Source Version:                {result.get('source_version')}")
    print(f" Key ID:                        {result.get('key_id')}")
    print(f" Manifest Version:              {result.get('manifest_version')}")
    print(f" Classification:                {result.get('classification')}")
    print(f" Key Available:                 {result.get('is_key_available')}")
    print(f" Key Active:                    {result.get('is_key_active')}")
    print(f" Key Revoked:                   {result.get('is_key_revoked')}")
    print(f" Physical Binary on Disk:       {result.get('source_file_present_on_disk')}")
    print(f" Binary Hash Matches Record:    {result.get('physical_binary_hash_verified')}")
    print(f" Verification Result:           {result.get('verification_result')}")
    if result.get("failure_category"):
        print(f" Failure Category:              {result.get('failure_category')}")
    if result.get("failure_reason"):
        print(f" Failure Reason:                {result.get('failure_reason')}")
    print("-" * 70)
    print(" Recommended Recovery Action:")
    print(f" {result.get('recommended_recovery_action')}")
    print("=" * 70 + "\n")

    sys.exit(0 if result.get("status") == "PASS" else 1)


if __name__ == "__main__":
    main()

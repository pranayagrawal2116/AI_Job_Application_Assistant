"""Dedicated Security Scan HMAC Signing, Verification, and Key Lifecycle Management.

Provides cryptographically separated signing and verification for persistent security scans
using RFC 8785 canonical JSON and HMAC-SHA256, with independent key rotation and long-term retention.
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from src.database.exceptions import (
    CrossUserAccessError,
    KeyRevokedError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.security.prompt_injection_detector import PromptInjectionScanResult, ThreatRecord
from src.utils.canonical_json import canonical_json_bytes
from src.utils.logger import setup_logger

logger = setup_logger("ScanSigner")

# Supported canonical manifest versions
SUPPORTED_MANIFEST_VERSIONS = {"v1", "v2"}

# Process-wide ephemeral key for development/testing when env secret is not set
_PROCESS_EPHEMERAL_KEY: Optional[bytes] = None


class ScanKeyManager:
    """Manages dedicated HMAC-SHA256 keys for security scans with long-term retention."""

    def __init__(
        self,
        active_key_id: Optional[str] = None,
        signing_key: Optional[Union[str, bytes]] = None,
        rotation_keys: Optional[Dict[str, Union[str, bytes]]] = None,
        db_manager: Optional[Any] = None,
    ):
        self._lock = threading.RLock()
        self._keys: Dict[str, bytes] = {}
        self._revoked_keys: Set[str] = set()
        self._db_manager = db_manager

        # Determine environment
        app_env = os.environ.get("APP_ENV", "development").lower()

        # 1. Resolve active key ID
        resolved_key_id = active_key_id or os.environ.get("SECURITY_SCAN_ACTIVE_KEY_ID", "scan_v1")
        if not resolved_key_id or not isinstance(resolved_key_id, str) or not resolved_key_id.strip():
            raise SecurityAuthorizationError(f"Invalid active key ID '{resolved_key_id}': cannot be empty.")
        resolved_key_id = resolved_key_id.strip()
        self.active_key_id = resolved_key_id

        # 2. Resolve primary signing key
        resolved_secret: Optional[bytes] = None
        if signing_key:
            resolved_secret = self._coerce_bytes(signing_key)
        else:
            env_secret = os.environ.get("SECURITY_SCAN_SIGNING_KEY")
            if env_secret:
                resolved_secret = self._coerce_bytes(env_secret)

        if not resolved_secret:
            if app_env == "production":
                raise SecurityAuthorizationError(
                    "Missing SECURITY_SCAN_SIGNING_KEY in production environment. "
                    "Cannot start without authoritative scan signing key."
                )
            # Ephemeral development/testing key - persistent across instances in the same process
            global _PROCESS_EPHEMERAL_KEY
            if _PROCESS_EPHEMERAL_KEY is None:
                _PROCESS_EPHEMERAL_KEY = secrets.token_bytes(32)
                logger.warning("Generating process-wide ephemeral development/testing security scan key.")
            resolved_secret = _PROCESS_EPHEMERAL_KEY

        self._register_key(resolved_key_id, resolved_secret, is_active=True)

        # 3. Resolve historical / rotation keys
        raw_rotation = rotation_keys
        if raw_rotation is None:
            env_rot = os.environ.get("SECURITY_SCAN_ROTATION_KEYS")
            if env_rot:
                try:
                    raw_rotation = json.loads(env_rot)
                except Exception as e:
                    if app_env == "production":
                        raise SecurityAuthorizationError(f"Malformed SECURITY_SCAN_ROTATION_KEYS in production: {e}")
                    logger.warning("Failed to parse SECURITY_SCAN_ROTATION_KEYS JSON: %s", e)

        if raw_rotation is not None:
            if not isinstance(raw_rotation, dict):
                if app_env == "production":
                    raise SecurityAuthorizationError("SECURITY_SCAN_ROTATION_KEYS must be a JSON object / dictionary.")
                logger.warning("SECURITY_SCAN_ROTATION_KEYS is not a dict.")
            else:
                for k_id, sec in raw_rotation.items():
                    self._register_key(k_id, sec, is_active=False)

    def _register_key(
        self,
        key_id: str,
        secret: Union[str, bytes],
        is_active: bool = False,
    ) -> None:
        """Registers a signing or verification key, enforcing strict entropy, non-reuse of action ticket keys, and key ID immutability."""
        if not key_id or not isinstance(key_id, str) or not key_id.strip():
            raise SecurityAuthorizationError(f"Invalid key ID '{key_id}': cannot be empty.")
        clean_key_id = key_id.strip()

        with self._lock:
            if clean_key_id in self._revoked_keys:
                raise SecurityAuthorizationError(f"Scan key ID '{clean_key_id}' is revoked.")

            if self._db_manager and hasattr(self._db_manager, "is_key_revoked"):
                if self._db_manager.is_key_revoked(clean_key_id):
                    self._revoked_keys.add(clean_key_id)
                    raise SecurityAuthorizationError(f"Scan key ID '{clean_key_id}' is revoked.")

            secret_bytes = self._coerce_bytes(secret)
            if len(secret_bytes) < 32:
                raise SecurityAuthorizationError(
                    f"Scan key '{clean_key_id}' must have at least 32 bytes (256 bits) of entropy."
                )

            prohibited = self._get_prohibited_action_ticket_keys()
            if secret_bytes in prohibited:
                raise SecurityAuthorizationError(
                    f"Security scan key '{clean_key_id}' cannot reuse ACTION_TICKET_SECRET_KEY or action ticket keys. "
                    "Cryptographic key separation is strictly enforced."
                )

            if clean_key_id in self._keys:
                if self._keys[clean_key_id] != secret_bytes:
                    raise SecurityAuthorizationError(
                        f"Cannot reuse existing key ID '{clean_key_id}' with different secret material."
                    )
                if is_active:
                    self.active_key_id = clean_key_id
                return

            self._keys[clean_key_id] = secret_bytes
            if is_active:
                self.active_key_id = clean_key_id

    def _get_prohibited_action_ticket_keys(self) -> Set[bytes]:
        """Collects all configured action-ticket secret keys to enforce strict cryptographic domain separation."""
        prohibited: Set[bytes] = set()
        action_ticket_secret = os.environ.get("ACTION_TICKET_SECRET_KEY")
        if action_ticket_secret:
            prohibited.add(self._coerce_bytes(action_ticket_secret))
        rot_env = os.environ.get("ACTION_TICKET_ROTATION_KEYS")
        if rot_env:
            try:
                rot_data = json.loads(rot_env)
                if isinstance(rot_data, dict):
                    for v in rot_data.values():
                        prohibited.add(self._coerce_bytes(v))
            except Exception as e:
                app_env = os.environ.get("APP_ENV", "development").lower()
                if app_env == "production":
                    raise SecurityAuthorizationError(f"Malformed ACTION_TICKET_ROTATION_KEYS in production: {e}")
        return prohibited

    @staticmethod
    def _coerce_bytes(val: Union[str, bytes]) -> bytes:
        if isinstance(val, bytes):
            return val
        if len(val) >= 64 and all(c in "0123456789abcdefABCDEF" for c in val):
            try:
                return bytes.fromhex(val)
            except ValueError:
                pass
        return val.encode("utf-8")

    def register_db_manager(self, db_manager: Any) -> None:
        self._db_manager = db_manager

    def get_signing_key(self) -> Tuple[str, bytes]:
        """Returns the active (key_id, secret_bytes) for new scan signatures."""
        with self._lock:
            if self.active_key_id in self._revoked_keys:
                raise KeyRevokedError(self.active_key_id)
            if self._db_manager and hasattr(self._db_manager, "is_key_revoked"):
                if self._db_manager.is_key_revoked(self.active_key_id):
                    self._revoked_keys.add(self.active_key_id)
                    raise KeyRevokedError(self.active_key_id)
            return self.active_key_id, self._keys[self.active_key_id]

    def get_verification_key(self, key_id: str) -> bytes:
        """Retrieves key for verifying a historical scan record.

        Raises:
            KeyRevokedError: If the key was explicitly revoked.
            SecurityAuthorizationError: If the key ID is unknown.
        """
        if not key_id or not isinstance(key_id, str) or not key_id.strip():
            raise SecurityAuthorizationError(f"Invalid verification key ID: '{key_id}'")
        clean_key_id = key_id.strip()

        with self._lock:
            if clean_key_id in self._revoked_keys:
                raise KeyRevokedError(clean_key_id)

            if self._db_manager and hasattr(self._db_manager, "is_key_revoked"):
                if self._db_manager.is_key_revoked(clean_key_id):
                    self._revoked_keys.add(clean_key_id)
                    raise KeyRevokedError(clean_key_id)

            if clean_key_id in self._keys:
                return self._keys[clean_key_id]

            raise SecurityAuthorizationError(f"Security scan verification key '{clean_key_id}' is unknown or unavailable.")

    def rotate_key(self, new_key_id: str, new_secret: Union[str, bytes]) -> None:
        """Rotates the active scan signing key, retaining previous keys for historical verification."""
        with self._lock:
            self._register_key(new_key_id, new_secret, is_active=True)
            logger.info("Rotated security scan signing key to active key '%s'.", self.active_key_id)

    def revoke_key(self, key_id: str, reason: str = "Key Revoked") -> None:
        """Revokes a key ID immediately and durably in SQLite."""
        if not key_id or not isinstance(key_id, str) or not key_id.strip():
            raise SecurityAuthorizationError(f"Invalid key ID to revoke: '{key_id}'")
        clean_key_id = key_id.strip()

        with self._lock:
            self._revoked_keys.add(clean_key_id)
            if self._db_manager:
                persisted = False
                if hasattr(self._db_manager, "record_key_revocation"):
                    try:
                        self._db_manager.record_key_revocation(key_id=clean_key_id, reason=reason)
                        persisted = True
                    except Exception as e:
                        logger.error("Failed to persist scan key revocation to DB: %s", e)
                        raise SecurityAuthorizationError(f"Durable scan key revocation failed for key '{clean_key_id}': {e}") from e
                elif hasattr(self._db_manager, "revoke_signing_key_approvals"):
                    try:
                        self._db_manager.revoke_signing_key_approvals(key_id=clean_key_id, reason=reason)
                        persisted = True
                    except Exception as e:
                        logger.error("Failed to persist scan key revocation to DB: %s", e)
                        raise SecurityAuthorizationError(f"Durable scan key revocation failed for key '{clean_key_id}': {e}") from e
                if not persisted:
                    raise SecurityAuthorizationError(f"Database manager lacks key revocation persistence for '{clean_key_id}'.")
            else:
                app_env = os.environ.get("APP_ENV", "development").lower()
                if app_env == "production":
                    raise SecurityAuthorizationError("Missing persistent database manager for durable key revocation in production.")

            logger.warning("Revoked security scan key '%s' (Reason: %s).", clean_key_id, reason)


class SecurityScanSigner:
    """Signs and verifies security scan records using RFC 8785 canonical JSON and HMAC-SHA256."""

    def __init__(self, key_manager: Optional[ScanKeyManager] = None, db_manager: Optional[Any] = None):
        if key_manager:
            self.key_manager = key_manager
            if db_manager:
                self.key_manager.register_db_manager(db_manager)
        else:
            self.key_manager = ScanKeyManager(db_manager=db_manager)

    def build_canonical_manifest(
        self,
        user_id: int,
        source_type: str,
        source_id: int,
        source_version: int,
        source_hash: str,
        snapshot_hash: Optional[str],
        scanner_version: str,
        policy_version: str,
        risk_score: float,
        classification: str,
        threats: List[ThreatRecord],
        scanned_at: str,
        key_id: str,
        manifest_version: Optional[str] = None,
        source_binary_hash: Optional[str] = None,
        source_binary_size_bytes: Optional[int] = None,
        source_binary_format: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Constructs the canonical scan manifest dictionary before signing."""
        if manifest_version is not None:
            if not isinstance(manifest_version, str) or manifest_version.strip() not in SUPPORTED_MANIFEST_VERSIONS:
                raise SecurityAuthorizationError(
                    f"Unsupported or invalid manifest_version '{manifest_version}'. "
                    f"Supported manifest versions: {sorted(SUPPORTED_MANIFEST_VERSIONS)}"
                )
            resolved_manifest_version = manifest_version.strip()
        else:
            resolved_manifest_version = "v2" if source_binary_hash is not None else "v1"

        sorted_threats = sorted(threats, key=lambda t: (t.start_offset, t.end_offset, t.rule_id))
        serialized_threats = [
            {
                "category": t.category,
                "confidence": round(float(t.confidence), 4),
                "end_offset": t.end_offset,
                "engine_id": t.engine_id,
                "explanation": t.explanation or "",
                "rule_id": t.rule_id,
                "severity": t.severity,
                "start_offset": t.start_offset,
            }
            for t in sorted_threats
        ]
        if resolved_manifest_version == "v1":
            return {
                "classification": classification,
                "key_id": key_id,
                "manifest_version": "v1",
                "policy_version": policy_version,
                "risk_score": round(float(risk_score), 4),
                "scanned_at": scanned_at,
                "scanner_version": scanner_version,
                "snapshot_hash": snapshot_hash or "",
                "source_hash": source_hash,
                "source_id": int(source_id),
                "source_type": source_type,
                "source_version": int(source_version),
                "threat_count": len(sorted_threats),
                "threats": serialized_threats,
                "user_id": int(user_id),
            }

        return {
            "classification": classification,
            "key_id": key_id,
            "manifest_version": "v2",
            "policy_version": policy_version,
            "risk_score": round(float(risk_score), 4),
            "scanned_at": scanned_at,
            "scanner_version": scanner_version,
            "snapshot_hash": snapshot_hash or "",
            "source_binary_format": source_binary_format,
            "source_binary_hash": source_binary_hash,
            "source_binary_size_bytes": source_binary_size_bytes,
            "source_hash": source_hash,
            "source_id": int(source_id),
            "source_type": source_type,
            "source_version": int(source_version),
            "threat_count": len(sorted_threats),
            "threats": serialized_threats,
            "user_id": int(user_id),
        }

    def sign_scan_result(
        self,
        user_id: int,
        source_type: str,
        source_id: int,
        source_version: int,
        source_hash: str,
        snapshot_hash: Optional[str],
        scan_result: PromptInjectionScanResult,
        scanned_at: Optional[str] = None,
        manifest_version: Optional[str] = None,
        source_binary_hash: Optional[str] = None,
        source_binary_size_bytes: Optional[int] = None,
        source_binary_format: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], str, str]:
        """Computes RFC 8785 canonical JSON bytes and signs with active HMAC-SHA256 key.

        Returns:
            Tuple of (manifest_dict, hmac_signature, key_id).
        """
        key_id, secret_bytes = self.key_manager.get_signing_key()
        timestamp = scanned_at or scan_result.scan_timestamp

        resolved_manifest_version = manifest_version or ("v2" if source_binary_hash is not None else "v1")

        manifest = self.build_canonical_manifest(
            user_id=user_id,
            source_type=source_type,
            source_id=source_id,
            source_version=source_version,
            source_hash=source_hash,
            snapshot_hash=snapshot_hash,
            scanner_version=scan_result.engine_version,
            policy_version=scan_result.policy_version,
            risk_score=scan_result.risk_score,
            classification=scan_result.classification,
            threats=scan_result.threats_detected,
            scanned_at=timestamp,
            key_id=key_id,
            manifest_version=resolved_manifest_version,
            source_binary_hash=source_binary_hash,
            source_binary_size_bytes=source_binary_size_bytes,
            source_binary_format=source_binary_format,
        )

        canonical_bytes = canonical_json_bytes(manifest)
        signature = hmac.new(secret_bytes, canonical_bytes, hashlib.sha256).hexdigest()
        return manifest, signature, key_id

    def verify_scan_record(
        self,
        expected_user_id: int,
        expected_source_type: str,
        expected_source_id: int,
        expected_source_version: int,
        expected_source_hash: str,
        expected_snapshot_hash: Optional[str],
        scan_row: Dict[str, Any],
        expected_source_binary_hash: Optional[str] = None,
        expected_source_binary_size_bytes: Optional[int] = None,
        expected_source_binary_format: Optional[str] = None,
    ) -> bool:
        """Verifies the HMAC signature and cryptographic consistency of a stored scan record.

        Raises:
            SecurityAuthorizationError: If signature is invalid, key is revoked, or hashes mismatch.
            CrossUserAccessError: If user_id does not match expected_user_id.
        """
        if hasattr(scan_row, "to_dict"):
            scan_row = scan_row.to_dict()

        row_user_id = scan_row.get("user_id")
        if row_user_id != expected_user_id:
            raise CrossUserAccessError(
                user_id=expected_user_id,
                target_user_id=row_user_id,
                resource=f"security_scans #{scan_row.get('id')}",
            )

        if scan_row.get("source_type") != expected_source_type:
            raise ValidationError(
                f"Source type mismatch: expected '{expected_source_type}', got '{scan_row.get('source_type')}'."
            )

        if scan_row.get("source_id") != expected_source_id:
            raise ValidationError(
                f"Source ID mismatch: expected '{expected_source_id}', got '{scan_row.get('source_id')}'."
            )

        if scan_row.get("source_version") != expected_source_version:
            raise ValidationError(
                f"Source version mismatch: expected '{expected_source_version}', got '{scan_row.get('source_version')}'."
            )

        if scan_row.get("source_hash") != expected_source_hash:
            raise SecurityAuthorizationError(
                f"Source hash discrepancy: current source hash '{expected_source_hash}' "
                f"does not match scanned hash '{scan_row.get('source_hash')}'."
            )

        if expected_snapshot_hash:
            row_snap = scan_row.get("snapshot_hash") or ""
            if row_snap != expected_snapshot_hash:
                raise SecurityAuthorizationError(
                    f"Snapshot hash discrepancy: current snapshot hash '{expected_snapshot_hash}' "
                    f"does not match scanned snapshot hash '{row_snap}'."
                )

        raw_manifest_version = scan_row.get("manifest_version")
        if not raw_manifest_version:
            manifest_version = "v2" if scan_row.get("source_binary_hash") is not None else "v1"
        else:
            if not isinstance(raw_manifest_version, str) or raw_manifest_version.strip() not in SUPPORTED_MANIFEST_VERSIONS:
                raise SecurityAuthorizationError(
                    f"Stored scan record #{scan_row.get('id')} has unsupported manifest_version '{raw_manifest_version}'. "
                    f"Supported manifest versions: {sorted(SUPPORTED_MANIFEST_VERSIONS)}"
                )
            manifest_version = raw_manifest_version.strip()

        row_bin_hash = scan_row.get("source_binary_hash")
        row_bin_size = scan_row.get("source_binary_size_bytes")
        row_bin_fmt = scan_row.get("source_binary_format")

        # Strict v2 enforcement: reject v1 records when expected binary provenance is supplied
        if expected_source_binary_hash is not None:
            if manifest_version == "v1":
                raise SecurityAuthorizationError(
                    f"Scan record #{scan_row.get('id')} has manifest version 'v1' lacking binary provenance, "
                    f"but binary provenance is required for this source. A 'v2' rescan is required."
                )

        if manifest_version == "v2":
            if expected_source_binary_hash is not None and row_bin_hash != expected_source_binary_hash:
                raise SecurityAuthorizationError(
                    f"Binary hash discrepancy: expected '{expected_source_binary_hash}', got '{row_bin_hash}'."
                )
            if expected_source_binary_size_bytes is not None and row_bin_size != expected_source_binary_size_bytes:
                raise SecurityAuthorizationError(
                    f"Binary size discrepancy: expected {expected_source_binary_size_bytes}, got {row_bin_size}."
                )
            if expected_source_binary_format is not None and row_bin_fmt != expected_source_binary_format:
                raise SecurityAuthorizationError(
                    f"Binary format discrepancy: expected '{expected_source_binary_format}', got '{row_bin_fmt}'."
                )

        key_id = scan_row.get("key_id")
        if not key_id:
            raise SecurityAuthorizationError("Stored scan record is missing key_id.")

        stored_signature = scan_row.get("hmac_signature")
        if not stored_signature:
            raise SecurityAuthorizationError("Stored scan record is missing hmac_signature.")

        # Reconstruct threats
        raw_threats_json = scan_row.get("threats_detected_json", "[]")
        try:
            threats_data = json.loads(raw_threats_json) if isinstance(raw_threats_json, str) else raw_threats_json
            threat_objs = [
                ThreatRecord(
                    rule_id=t.get("rule_id", ""),
                    category=t.get("category", ""),
                    severity=t.get("severity", ""),
                    confidence=float(t.get("confidence", 1.0)),
                    start_offset=int(t.get("start_offset", 0)),
                    end_offset=int(t.get("end_offset", 0)),
                    explanation=t.get("explanation", ""),
                    engine_id=t.get("engine_id", ""),
                )
                for t in threats_data
            ]
        except Exception as e:
            raise SecurityAuthorizationError(f"Malformed threats_detected_json in scan record: {e}")

        verification_key = self.key_manager.get_verification_key(key_id)

        manifest = self.build_canonical_manifest(
            user_id=row_user_id,
            source_type=scan_row["source_type"],
            source_id=scan_row["source_id"],
            source_version=scan_row["source_version"],
            source_hash=scan_row["source_hash"],
            snapshot_hash=scan_row.get("snapshot_hash"),
            scanner_version=scan_row["scanner_version"],
            policy_version=scan_row["policy_version"],
            risk_score=scan_row["risk_score"],
            classification=scan_row["classification"],
            threats=threat_objs,
            scanned_at=scan_row["scanned_at"],
            key_id=key_id,
            manifest_version=manifest_version,
            source_binary_hash=row_bin_hash,
            source_binary_size_bytes=row_bin_size,
            source_binary_format=row_bin_fmt,
        )

        canonical_bytes = canonical_json_bytes(manifest)
        computed_signature = hmac.new(verification_key, canonical_bytes, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(computed_signature, stored_signature):
            raise SecurityAuthorizationError(
                f"Cryptographic signature verification failed for scan record #{scan_row.get('id')}. "
                "The scan record has been tampered with or modified."
            )

        return True

        return True

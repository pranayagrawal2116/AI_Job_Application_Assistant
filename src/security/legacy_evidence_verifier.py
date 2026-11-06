"""Dedicated Cryptographic Legacy Evidence Verification & Artifact Resolution Engine.

Phase 9.1.2.6 Architecture v2.1.1 Implementation.
Provides authoritative, independent verification of archival evidence artifacts
asserting pre-Phase-9.1.1 provenance for historical job descriptions.

Core Security Principle:
An evidence reference is not proof of evidence.
Every legacy exception must be backed by an independently resolvable,
cryptographically authentic, and strictly bound evidence artifact.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from src.database.exceptions import (
    KeyRevokedError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.utils.canonical_json import canonical_json_bytes
from src.utils.logger import setup_logger

logger = setup_logger("LegacyEvidenceVerifier")

# Strict allowlist of supported historical evidence types (Section 3)
SUPPORTED_EVIDENCE_TYPES: Set[str] = {
    "archival_import_manifest",
    "historical_import_manifest",
    "pre_phase9_signed_backup",
}

# Strict allowlist of supported cryptographic signature schemes (Section 3.2)
SUPPORTED_SIGNATURE_ALGORITHMS: Set[str] = {
    "HMAC-SHA256",
    "Ed25519",
}

# Recognized historical migration boundaries asserting pre-Phase-9 provenance
VALID_MIGRATION_BOUNDARIES: Set[str] = {
    "pre_phase_9_1_1",
    "pre_phase_9_0_0",
}

# Default authorized attesting principals for system migration
DEFAULT_AUTHORIZED_ATTESTING_PRINCIPALS: frozenset[str] = frozenset({
    "system_migration_authority",
    "system_migration_coordinator",
    "authorized_system_migration",
    "system_migration",
    "authorized_migration_principal",
    "authorized_migration_coordinator",
    "test_synthetic_migration_coordinator",
})

# Private sentinel token preventing arbitrary instantiation of VerifiedLegacyEvidence
_VERIFICATION_TOKEN = object()


@dataclass(frozen=True)
class VerifiedLegacyEvidence:
    """Immutable verified legacy evidence container.

    Can only be constructed by LegacyEvidenceVerifier.verify() after
    successful cryptographic resolution and verification.
    """

    _token: Any
    evidence_type: str
    evidence_reference_id: str
    evidence_artifact_hash: str
    evidence_payload_hash: str
    user_id: int
    job_description_id: int
    source_snapshot_hash: str
    migration_boundary: str
    issuer_id: str
    key_id: str
    signature_algorithm: str
    evidence_signature: str
    verified_at: str
    attested_by: str

    def __post_init__(self) -> None:
        if self._token is not _VERIFICATION_TOKEN:
            raise SecurityAuthorizationError(
                "VerifiedLegacyEvidence cannot be instantiated directly. "
                "Must be produced by LegacyEvidenceVerifier.verify()."
            )


class LegacyEvidenceTrustStore:
    """Manages trusted root keys, public keys, and authorized issuers for archival evidence.

    Cryptographic Assurance Notice (Phase 9.1.2.7):
    - Ed25519 provides asymmetric digital signatures (PureEdDSA, RFC 8032) where the verifier
      only holds the public key. This provides independent third-party verifiable non-repudiation
      and is mandatory under production algorithm policy ('production' or 'ed25519_only').
    - HMAC-SHA256 is a symmetric Message Authentication Code (MAC) where the verifier and signer
      share the identical secret. It does not provide third-party non-repudiation when the runtime
      holds the shared secret, and is permitted only under 'permissive' policy (e.g. testing).
    """

    def __init__(
        self,
        trusted_keys: Optional[Dict[str, Union[str, bytes]]] = None,
        trusted_issuers: Optional[Set[str]] = None,
        revoked_keys: Optional[Set[str]] = None,
        trusted_attesting_principals: Optional[Set[str]] = None,
        revoked_principals: Optional[Set[str]] = None,
        algorithm_policy: Optional[str] = None,
        db_manager: Optional[Any] = None,
    ):
        self._lock = threading.RLock()
        self._keys: Dict[str, bytes] = {}
        self._key_algorithms: Dict[str, str] = {}
        self._trusted_issuers: Set[str] = set()
        self._revoked_keys: Set[str] = set()
        self._trusted_attesting_principals: Set[str] = set()
        self._revoked_principals: Set[str] = set()
        self._db_manager = db_manager

        # Determine algorithm policy
        env_policy = os.environ.get("LEGACY_EVIDENCE_POLICY")
        chosen_policy = (algorithm_policy or env_policy or "permissive").strip().lower()
        if chosen_policy not in ("permissive", "production", "ed25519_only"):
            raise SecurityAuthorizationError(f"Unknown legacy evidence algorithm policy '{chosen_policy}'")
        self.algorithm_policy = chosen_policy

        # Stage configuration for atomic validation
        staged_revoked_keys: Set[str] = set()
        staged_issuers: Set[str] = set()
        staged_principals: Set[str] = set(DEFAULT_AUTHORIZED_ATTESTING_PRINCIPALS)
        staged_revoked_principals: Set[str] = set()
        staged_keys: List[Tuple[str, Union[str, bytes], str]] = []

        # 1. Load from environment if available (fail closed on malformed JSON)
        env_revoked = os.environ.get("LEGACY_EVIDENCE_REVOKED_KEYS")
        if env_revoked:
            try:
                parsed_revoked = json.loads(env_revoked)
                if not isinstance(parsed_revoked, list):
                    raise SecurityAuthorizationError("LEGACY_EVIDENCE_REVOKED_KEYS must be a JSON array")
                for k in parsed_revoked:
                    staged_revoked_keys.add(str(k))
            except json.JSONDecodeError as e:
                raise SecurityAuthorizationError(f"Malformed JSON in LEGACY_EVIDENCE_REVOKED_KEYS: {e}")

        env_issuers = os.environ.get("LEGACY_EVIDENCE_TRUSTED_ISSUERS")
        if env_issuers:
            try:
                parsed_issuers = json.loads(env_issuers)
                if not isinstance(parsed_issuers, list):
                    raise SecurityAuthorizationError("LEGACY_EVIDENCE_TRUSTED_ISSUERS must be a JSON array")
                for iss in parsed_issuers:
                    staged_issuers.add(str(iss))
            except json.JSONDecodeError as e:
                raise SecurityAuthorizationError(f"Malformed JSON in LEGACY_EVIDENCE_TRUSTED_ISSUERS: {e}")

        env_principals = os.environ.get("LEGACY_EVIDENCE_TRUSTED_PRINCIPALS")
        if env_principals:
            try:
                parsed_principals = json.loads(env_principals)
                if not isinstance(parsed_principals, list):
                    raise SecurityAuthorizationError("LEGACY_EVIDENCE_TRUSTED_PRINCIPALS must be a JSON array")
                for p in parsed_principals:
                    staged_principals.add(str(p))
            except json.JSONDecodeError as e:
                raise SecurityAuthorizationError(f"Malformed JSON in LEGACY_EVIDENCE_TRUSTED_PRINCIPALS: {e}")

        env_keys = os.environ.get("LEGACY_EVIDENCE_TRUSTED_KEYS")
        if env_keys:
            try:
                parsed_keys = json.loads(env_keys)
                if not isinstance(parsed_keys, dict):
                    raise SecurityAuthorizationError("LEGACY_EVIDENCE_TRUSTED_KEYS must be a JSON object")
                for k_id, val in parsed_keys.items():
                    if isinstance(val, dict):
                        k_bytes = val.get("key") or val.get("key_bytes") or ""
                        k_algo = val.get("algorithm", "HMAC-SHA256")
                        staged_keys.append((str(k_id), k_bytes, k_algo))
                    else:
                        staged_keys.append((str(k_id), val, "HMAC-SHA256"))
            except json.JSONDecodeError as e:
                raise SecurityAuthorizationError(f"Malformed JSON in LEGACY_EVIDENCE_TRUSTED_KEYS: {e}")

        # 2. Merge caller-supplied parameters
        if revoked_keys:
            for k in revoked_keys:
                staged_revoked_keys.add(str(k))

        if trusted_issuers:
            for iss in trusted_issuers:
                staged_issuers.add(str(iss))

        if trusted_attesting_principals:
            for p in trusted_attesting_principals:
                staged_principals.add(str(p))

        if revoked_principals:
            for rp in revoked_principals:
                staged_revoked_principals.add(str(rp))

        if trusted_keys:
            for k_id, k_val in trusted_keys.items():
                staged_keys.append((str(k_id), k_val, "HMAC-SHA256"))

        # 3. Validate and activate atomically
        active_revoked: Set[str] = set()
        for k in staged_revoked_keys:
            clean_k = (k or "").strip()
            if not clean_k:
                raise SecurityAuthorizationError("Revoked key ID cannot be empty or whitespace.")
            active_revoked.add(clean_k)

        active_issuers: Set[str] = set()
        for iss in staged_issuers:
            clean_iss = (iss or "").strip()
            if not clean_iss:
                raise SecurityAuthorizationError("Issuer ID cannot be empty or whitespace.")
            if clean_iss.startswith("user_") or clean_iss == "candidate_user":
                raise SecurityAuthorizationError(f"Candidate user '{clean_iss}' cannot be an issuer.")
            active_issuers.add(clean_iss)

        active_principals: Set[str] = set()
        for p in staged_principals:
            clean_p = (p or "").strip()
            if not clean_p:
                raise SecurityAuthorizationError("Attesting principal cannot be empty or whitespace.")
            if clean_p.startswith("user_") or clean_p == "candidate_user":
                raise SecurityAuthorizationError(f"Candidate user '{clean_p}' cannot be an attesting principal.")
            active_principals.add(clean_p)

        for rp in staged_revoked_principals:
            clean_rp = (rp or "").strip()
            if not clean_rp:
                raise SecurityAuthorizationError("Revoked principal ID cannot be empty or whitespace.")
            active_principals.discard(clean_rp)

        active_keys: Dict[str, bytes] = {}
        active_algos: Dict[str, str] = {}

        for k_id, k_val, k_algo in staged_keys:
            clean_id = (k_id or "").strip()
            if not clean_id:
                raise SecurityAuthorizationError("Key ID cannot be empty or whitespace.")
            if clean_id in active_revoked:
                raise SecurityAuthorizationError(f"Cannot register key '{clean_id}': key is revoked.")
            if k_algo not in SUPPORTED_SIGNATURE_ALGORITHMS:
                raise SecurityAuthorizationError(
                    f"Unsupported signature algorithm '{k_algo}'. Supported: {sorted(SUPPORTED_SIGNATURE_ALGORITHMS)}"
                )

            if self.algorithm_policy in ("production", "ed25519_only") and k_algo != "Ed25519":
                raise SecurityAuthorizationError(
                    f"Algorithm '{k_algo}' is rejected: production policy enforces Ed25519 asymmetric digital signatures only."
                )

            coerced = self._coerce_bytes(k_val)
            if k_algo == "HMAC-SHA256":
                if len(coerced) < 32:
                    raise SecurityAuthorizationError(
                        f"Legacy evidence signing key '{clean_id}' has insufficient entropy "
                        f"({len(coerced)} bytes < minimum 32 bytes / 256 bits)."
                    )
            elif k_algo == "Ed25519":
                from cryptography.hazmat.primitives.asymmetric import ed25519
                if len(coerced) != 32:
                    raise SecurityAuthorizationError(
                        f"Ed25519 public key '{clean_id}' must be exactly 32 bytes (got {len(coerced)} bytes)."
                    )
                try:
                    _ = ed25519.Ed25519PublicKey.from_public_bytes(coerced)
                except Exception as e:
                    raise SecurityAuthorizationError(f"Invalid Ed25519 public key '{clean_id}': {e}")

            # Check collision within staged_keys
            if clean_id in active_keys:
                if active_keys[clean_id] == coerced and active_algos[clean_id] == k_algo:
                    continue  # Idempotent confirmation
                if active_keys[clean_id] != coerced:
                    raise SecurityAuthorizationError(
                        f"Trusted key ID '{clean_id}' already registered with different key material. Immutability violation."
                    )
                if active_algos[clean_id] != k_algo:
                    raise SecurityAuthorizationError(
                        f"Trusted key ID '{clean_id}' already registered with different algorithm ('{active_algos[clean_id]}' != '{k_algo}'). Immutability violation."
                    )

            active_keys[clean_id] = coerced
            active_algos[clean_id] = k_algo

        # Only after 100% of validation passes do we activate state
        self._keys = active_keys
        self._key_algorithms = active_algos
        self._trusted_issuers = active_issuers
        self._revoked_keys = active_revoked
        self._trusted_attesting_principals = active_principals
        self._revoked_principals = set(staged_revoked_principals)

    @staticmethod
    def _coerce_bytes(val: Union[str, bytes]) -> bytes:
        if isinstance(val, bytes):
            if b"-----BEGIN PUBLIC KEY-----" in val:
                from cryptography.hazmat.primitives import serialization
                try:
                    key_obj = serialization.load_pem_public_key(val)
                    if hasattr(key_obj, "public_bytes_raw"):
                        return key_obj.public_bytes_raw()
                except Exception:
                    pass
            return val
        if isinstance(val, str):
            if "-----BEGIN PUBLIC KEY-----" in val:
                from cryptography.hazmat.primitives import serialization
                try:
                    key_obj = serialization.load_pem_public_key(val.encode("utf-8"))
                    if hasattr(key_obj, "public_bytes_raw"):
                        return key_obj.public_bytes_raw()
                except Exception:
                    pass
            if len(val) >= 64 and all(c in "0123456789abcdefABCDEF" for c in val):
                try:
                    return bytes.fromhex(val)
                except ValueError:
                    pass
            return val.encode("utf-8")
        return bytes(val)

    def register_trusted_issuer(self, issuer_id: str) -> None:
        """Registers an authorized evidence issuer identity."""
        clean_issuer = (issuer_id or "").strip()
        if not clean_issuer:
            raise SecurityAuthorizationError("Invalid issuer_id: cannot be empty or whitespace.")
        if clean_issuer.startswith("user_") or clean_issuer == "candidate_user":
            raise SecurityAuthorizationError(f"Candidate user '{clean_issuer}' cannot be an evidence issuer.")
        with self._lock:
            self._trusted_issuers.add(clean_issuer)

    def register_trusted_attesting_principal(self, principal_id: str) -> None:
        """Registers an authorized migration attesting principal."""
        clean_p = (principal_id or "").strip()
        if not clean_p:
            raise SecurityAuthorizationError("Invalid principal_id: cannot be empty or whitespace.")
        with self._lock:
            if clean_p in self._revoked_principals:
                raise SecurityAuthorizationError(f"Cannot register attesting principal '{clean_p}': principal has been revoked.")
            if clean_p.startswith("user_") or clean_p == "candidate_user":
                raise SecurityAuthorizationError(f"Candidate user '{clean_p}' cannot be an attesting principal.")
            self._trusted_attesting_principals.add(clean_p)

    def revoke_attesting_principal(self, principal_id: str) -> None:
        """Revokes an attesting principal."""
        clean_p = (principal_id or "").strip()
        if not clean_p:
            raise SecurityAuthorizationError("Cannot revoke empty principal_id")
        with self._lock:
            self._revoked_principals.add(clean_p)
            self._trusted_attesting_principals.discard(clean_p)

    def is_attesting_principal_trusted(self, principal_id: str) -> bool:
        """Verifies whether an attesting principal is authorized and not revoked."""
        clean_p = (principal_id or "").strip()
        if not clean_p:
            return False
        with self._lock:
            if clean_p in self._revoked_principals:
                return False
            return clean_p in self._trusted_attesting_principals

    def register_trusted_key(
        self,
        key_id: str,
        key_bytes: Union[str, bytes],
        algorithm: str = "HMAC-SHA256",
    ) -> None:
        """Registers a trusted signing key or public key with strict immutability checks."""
        clean_id = (key_id or "").strip()
        if not clean_id:
            raise SecurityAuthorizationError("Invalid key_id: cannot be empty or whitespace.")

        with self._lock:
            if self.is_key_revoked(clean_id):
                raise SecurityAuthorizationError(f"Cannot register key '{clean_id}': key ID has been revoked.")

            if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
                raise SecurityAuthorizationError(
                    f"Unsupported signature algorithm '{algorithm}'. Supported: {sorted(SUPPORTED_SIGNATURE_ALGORITHMS)}"
                )

            if self.algorithm_policy in ("production", "ed25519_only") and algorithm != "Ed25519":
                raise SecurityAuthorizationError(
                    f"Algorithm '{algorithm}' is rejected: production policy enforces Ed25519 asymmetric digital signatures only."
                )

            coerced = self._coerce_bytes(key_bytes)
            if algorithm == "HMAC-SHA256":
                if len(coerced) < 32:
                    raise SecurityAuthorizationError(
                        f"Legacy evidence signing key '{clean_id}' has insufficient entropy "
                        f"({len(coerced)} bytes < minimum 32 bytes / 256 bits)."
                    )
            elif algorithm == "Ed25519":
                from cryptography.hazmat.primitives.asymmetric import ed25519
                if len(coerced) != 32:
                    raise SecurityAuthorizationError(
                        f"Ed25519 public key '{clean_id}' must be exactly 32 bytes (got {len(coerced)} bytes)."
                    )
                try:
                    _ = ed25519.Ed25519PublicKey.from_public_bytes(coerced)
                except Exception as e:
                    raise SecurityAuthorizationError(f"Invalid Ed25519 public key '{clean_id}': {e}")

            if clean_id in self._keys:
                existing_bytes = self._keys[clean_id]
                existing_algo = self._key_algorithms.get(clean_id)
                if existing_bytes == coerced and existing_algo == algorithm:
                    logger.debug("Idempotent registration of trusted key '%s'.", clean_id)
                    return
                if existing_bytes != coerced:
                    raise SecurityAuthorizationError(
                        f"Trusted key ID '{clean_id}' already registered with different key material. Immutability violation."
                    )
                if existing_algo != algorithm:
                    raise SecurityAuthorizationError(
                        f"Trusted key ID '{clean_id}' already registered with different algorithm ('{existing_algo}' != '{algorithm}'). Immutability violation."
                    )

            self._keys[clean_id] = coerced
            self._key_algorithms[clean_id] = algorithm

    def revoke_key(self, key_id: str) -> None:
        """Revokes a trusted key ID."""
        clean_id = (key_id or "").strip()
        if not clean_id:
            return
        with self._lock:
            self._revoked_keys.add(clean_id)

    def has_keys(self) -> bool:
        """Returns True if any trusted keys are configured."""
        with self._lock:
            return len(self._keys) > 0

    def is_key_revoked(self, key_id: str) -> bool:
        """Checks if a key is revoked in memory or database."""
        clean_id = (key_id or "").strip()
        with self._lock:
            if clean_id in self._revoked_keys:
                return True
            if self._db_manager and hasattr(self._db_manager, "is_key_revoked"):
                if self._db_manager.is_key_revoked(clean_id):
                    self._revoked_keys.add(clean_id)
                    return True
        return False

    def get_key(self, key_id: str) -> Tuple[bytes, str]:
        """Retrieves key bytes and algorithm, raising error if revoked or unknown."""
        clean_id = (key_id or "").strip()
        if not clean_id:
            raise SecurityAuthorizationError("Invalid empty key_id")

        with self._lock:
            if self.is_key_revoked(clean_id):
                raise KeyRevokedError(clean_id)

            if clean_id not in self._keys:
                raise SecurityAuthorizationError(
                    f"Legacy evidence signing key '{clean_id}' is unknown or not configured in trust root."
                )

            return self._keys[clean_id], self._key_algorithms.get(clean_id, "HMAC-SHA256")

    def is_issuer_trusted(self, issuer_id: str) -> bool:
        """Verifies whether the issuer identity is authorized."""
        clean_issuer = (issuer_id or "").strip()
        if not clean_issuer:
            return False
        with self._lock:
            return clean_issuer in self._trusted_issuers


class LegacyEvidenceResolver(ABC):
    """Abstract resolver for retrieving historical evidence artifacts."""

    @abstractmethod
    def resolve_artifact(
        self,
        evidence_type: str,
        evidence_reference_id: str,
    ) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        """Resolves artifact raw bytes and parsed dict, or None if not found."""
        pass


class InMemoryEvidenceResolver(LegacyEvidenceResolver):
    """In-memory resolver holding pre-registered evidence artifacts."""

    def __init__(self, artifacts: Optional[Dict[Tuple[str, str], bytes]] = None):
        self._artifacts: Dict[Tuple[str, str], bytes] = dict(artifacts or {})
        self._lock = threading.RLock()

    def register_artifact(self, evidence_type: str, evidence_reference_id: str, artifact_bytes: bytes) -> None:
        with self._lock:
            self._artifacts[(evidence_type.strip(), evidence_reference_id.strip())] = artifact_bytes

    def resolve_artifact(
        self,
        evidence_type: str,
        evidence_reference_id: str,
    ) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        clean_type = (evidence_type or "").strip()
        clean_ref = (evidence_reference_id or "").strip()
        with self._lock:
            raw_bytes = self._artifacts.get((clean_type, clean_ref))
            if raw_bytes is None:
                return None
            try:
                parsed = json.loads(raw_bytes.decode("utf-8"))
                if not isinstance(parsed, dict):
                    return None
                return raw_bytes, parsed
            except Exception:
                return None


class FilesystemEvidenceResolver(LegacyEvidenceResolver):
    """Filesystem resolver loading signed archival artifacts from an isolated directory."""

    def __init__(self, base_dir: Union[str, Path]):
        self.base_dir = Path(base_dir).resolve()

    def resolve_artifact(
        self,
        evidence_type: str,
        evidence_reference_id: str,
    ) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        clean_type = (evidence_type or "").strip()
        clean_ref = (evidence_reference_id or "").strip()

        # Sanitize against path traversal
        if ".." in clean_type or "/" in clean_type or "\\" in clean_type or "\x00" in clean_type:
            logger.warning("Path traversal attempt in evidence_type: %s", clean_type)
            return None
        if ".." in clean_ref or "/" in clean_ref or "\\" in clean_ref or "\x00" in clean_ref:
            logger.warning("Path traversal attempt in evidence_reference_id: %s", clean_ref)
            return None

        target_file = (self.base_dir / clean_type / f"{clean_ref}.json").resolve()
        try:
            target_file.relative_to(self.base_dir)
        except ValueError:
            logger.warning("Target file escaped base_dir: %s", target_file)
            return None

        if not target_file.is_file():
            return None

        try:
            raw_bytes = target_file.read_bytes()
            parsed = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(parsed, dict):
                return None
            return raw_bytes, parsed
        except Exception as e:
            logger.warning("Failed to read evidence artifact %s: %s", target_file, e)
            return None


# Global process-wide default resolver and trust store (can be set during test/app startup)
_DEFAULT_RESOLVER: Optional[LegacyEvidenceResolver] = None
_DEFAULT_TRUST_STORE: Optional[LegacyEvidenceTrustStore] = None


def set_default_evidence_resolver(resolver: Optional[LegacyEvidenceResolver]) -> None:
    global _DEFAULT_RESOLVER
    _DEFAULT_RESOLVER = resolver


def get_default_evidence_resolver() -> Optional[LegacyEvidenceResolver]:
    return _DEFAULT_RESOLVER


def set_default_evidence_trust_store(trust_store: Optional[LegacyEvidenceTrustStore]) -> None:
    global _DEFAULT_TRUST_STORE
    _DEFAULT_TRUST_STORE = trust_store


def get_default_evidence_trust_store() -> Optional[LegacyEvidenceTrustStore]:
    return _DEFAULT_TRUST_STORE


def create_signed_evidence_artifact(
    evidence_type: str,
    evidence_reference_id: str,
    issuer_id: str,
    key_id: str,
    signing_key: Union[str, bytes, Any],
    entries: List[Dict[str, Any]],
    signature_algorithm: str = "HMAC-SHA256",
    migration_boundary: str = "pre_phase_9_1_1",
    issued_at: Optional[str] = None,
    attesting_principal: Optional[str] = None,
) -> Tuple[bytes, Dict[str, Any]]:
    """Helper for authorized migration authorities and tests to produce a canonical signed evidence artifact."""
    if evidence_type not in SUPPORTED_EVIDENCE_TYPES:
        raise ValidationError(f"Unsupported evidence_type '{evidence_type}'")
    if signature_algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ValidationError(f"Unsupported signature_algorithm '{signature_algorithm}'")
    if migration_boundary not in VALID_MIGRATION_BOUNDARIES:
        raise ValidationError(f"Invalid migration_boundary '{migration_boundary}'")

    issued = issued_at or datetime.now(timezone.utc).isoformat()

    payload_to_sign: Dict[str, Any] = {
        "evidence_type": evidence_type,
        "evidence_reference_id": evidence_reference_id,
        "issuer_id": issuer_id,
        "key_id": key_id,
        "signature_algorithm": signature_algorithm,
        "migration_boundary": migration_boundary,
        "issued_at": issued,
        "entries": entries,
    }
    if attesting_principal:
        payload_to_sign["attesting_principal"] = attesting_principal.strip()

    payload_bytes = canonical_json_bytes(payload_to_sign)

    # Compute digital signature
    if signature_algorithm == "HMAC-SHA256":
        key_bytes = LegacyEvidenceTrustStore._coerce_bytes(signing_key)
        signature = hmac.new(key_bytes, payload_bytes, hashlib.sha256).hexdigest()
    elif signature_algorithm == "Ed25519":
        from cryptography.hazmat.primitives.asymmetric import ed25519

        if isinstance(signing_key, ed25519.Ed25519PrivateKey):
            priv_key = signing_key
        else:
            key_bytes = LegacyEvidenceTrustStore._coerce_bytes(signing_key)
            priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
        raw_sig = priv_key.sign(payload_bytes)
        signature = raw_sig.hex()
    else:
        raise ValidationError(f"Unhandled algorithm '{signature_algorithm}'")

    artifact_dict = dict(payload_to_sign)
    artifact_dict["signature"] = signature

    raw_artifact_bytes = json.dumps(artifact_dict, indent=2, sort_keys=True).encode("utf-8")
    return raw_artifact_bytes, artifact_dict


class LegacyEvidenceVerifier:
    """Dedicated verifier enforcing cryptographic provenance for historical job descriptions."""

    def __init__(
        self,
        trust_store: Optional[LegacyEvidenceTrustStore] = None,
        resolver: Optional[LegacyEvidenceResolver] = None,
        db_manager: Optional[Any] = None,
    ):
        self.trust_store = trust_store or get_default_evidence_trust_store() or LegacyEvidenceTrustStore(db_manager=db_manager)
        self.resolver = resolver or get_default_evidence_resolver()
        self.db_manager = db_manager

    def set_resolver(self, resolver: Optional[LegacyEvidenceResolver]) -> None:
        self.resolver = resolver

    def verify(
        self,
        evidence_type: str,
        evidence_reference_id: str,
        user_id: int,
        job_description_id: int,
        source_snapshot_hash: str,
        attesting_principal: str,
    ) -> VerifiedLegacyEvidence:
        """Independently resolves and verifies an archival evidence artifact.

        Enforces:
        1. Allowlisted evidence type.
        2. Authorized attesting principal (non-empty, non-candidate user, registered in trust store).
        3. Artifact resolution (fails closed if artifact missing).
        4. Artifact SHA-256 hash computation.
        5. Exact metadata equality (type, reference ID, migration boundary).
        6. Trusted issuer identity (not self-attested, authorized in trust store).
        7. Trusted, unrevoked key ID with supported algorithm matching policy.
        8. Cryptographic digital signature verification over canonical payload bytes.
        9. Exact entry binding: artifact must explicitly list (user_id, job_description_id, source_snapshot_hash).
        """
        # 1. Evidence type allowlist
        clean_type = (evidence_type or "").strip()
        if clean_type not in SUPPORTED_EVIDENCE_TYPES:
            raise SecurityAuthorizationError(
                f"Evidence type '{clean_type}' is not on the supported allowlist: {sorted(SUPPORTED_EVIDENCE_TYPES)}"
            )

        # 2. Attesting principal authorization
        clean_principal = (attesting_principal or "").strip()
        if not clean_principal:
            raise SecurityAuthorizationError("Attesting principal is required and cannot be empty.")

        # Candidate user cannot attest own source
        if clean_principal in (f"user_{user_id}", str(user_id), "candidate_user") or clean_principal.startswith("candidate_"):
            raise SecurityAuthorizationError(
                f"Candidate user '{clean_principal}' cannot self-attest own source as historical evidence."
            )

        if not self.trust_store.is_attesting_principal_trusted(clean_principal):
            raise SecurityAuthorizationError(
                f"Attesting principal '{clean_principal}' is not authorized in trust store."
            )

        clean_ref = (evidence_reference_id or "").strip()
        if not clean_ref:
            raise SecurityAuthorizationError("Evidence reference ID cannot be empty.")

        # 3. Resolve artifact
        if self.resolver is None:
            raise SecurityAuthorizationError(
                f"No evidence resolver is configured. Cannot resolve evidence artifact '{clean_ref}'."
            )

        resolution = self.resolver.resolve_artifact(clean_type, clean_ref)
        if resolution is None:
            raise SecurityAuthorizationError(
                f"Referenced evidence artifact '{clean_ref}' of type '{clean_type}' could not be resolved or found."
            )

        artifact_bytes, artifact_dict = resolution
        artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()

        # 4. Validate artifact structure and fields
        if not isinstance(artifact_dict, dict):
            raise SecurityAuthorizationError(f"Evidence artifact '{clean_ref}' is not a valid JSON dictionary.")

        art_type = artifact_dict.get("evidence_type")
        if art_type != clean_type:
            raise SecurityAuthorizationError(
                f"Evidence artifact type mismatch: expected '{clean_type}', artifact declared '{art_type}'."
            )

        art_ref = artifact_dict.get("evidence_reference_id")
        if art_ref != clean_ref:
            raise SecurityAuthorizationError(
                f"Evidence artifact reference mismatch: expected '{clean_ref}', artifact declared '{art_ref}'."
            )

        algorithm = artifact_dict.get("signature_algorithm")
        if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise SecurityAuthorizationError(
                f"Evidence artifact signature algorithm '{algorithm}' is unsupported. "
                f"Supported: {sorted(SUPPORTED_SIGNATURE_ALGORITHMS)}"
            )

        if self.trust_store.algorithm_policy in ("production", "ed25519_only") and algorithm != "Ed25519":
            raise SecurityAuthorizationError(
                f"Evidence artifact signature algorithm '{algorithm}' is rejected: "
                "production policy requires Ed25519 asymmetric digital signatures."
            )

        boundary = artifact_dict.get("migration_boundary")
        if boundary not in VALID_MIGRATION_BOUNDARIES:
            raise SecurityAuthorizationError(
                f"Evidence artifact asserts invalid or missing historical migration boundary '{boundary}'."
            )

        issuer_id = (artifact_dict.get("issuer_id") or "").strip()
        if not issuer_id:
            raise SecurityAuthorizationError(f"Evidence artifact '{clean_ref}' lacks mandatory issuer_id.")

        if issuer_id in (f"user_{user_id}", str(user_id), "candidate_user") or issuer_id.startswith("candidate_"):
            raise SecurityAuthorizationError(
                f"Evidence artifact '{clean_ref}' issuer '{issuer_id}' represents untrusted candidate self-attestation."
            )

        if not self.trust_store.is_issuer_trusted(issuer_id):
            raise SecurityAuthorizationError(
                f"Evidence issuer '{issuer_id}' is unknown or not configured in trust store."
            )

        # Check explicit bound principal in artifact if present
        bound_principal = artifact_dict.get("attesting_principal") or artifact_dict.get("authorized_principal")
        if bound_principal and str(bound_principal).strip() != clean_principal:
            raise SecurityAuthorizationError(
                f"Evidence artifact '{clean_ref}' explicitly binds attesting principal '{bound_principal}', "
                f"which does not match verifying principal '{clean_principal}'."
            )

        key_id = (artifact_dict.get("key_id") or "").strip()
        if not key_id:
            raise SecurityAuthorizationError(f"Evidence artifact '{clean_ref}' lacks mandatory key_id.")

        # Key lookup (raises KeyRevokedError or SecurityAuthorizationError)
        key_bytes, expected_algo = self.trust_store.get_key(key_id)
        if algorithm != expected_algo:
            raise SecurityAuthorizationError(
                f"Algorithm mismatch for key '{key_id}': artifact claims '{algorithm}', trust store requires '{expected_algo}'."
            )

        signature = artifact_dict.get("signature")
        if not signature or not isinstance(signature, str) or not signature.strip():
            raise SecurityAuthorizationError(f"Evidence artifact '{clean_ref}' lacks a digital signature.")

        # 5. Extract payload without signature and verify cryptographic signature
        payload_to_verify = {k: v for k, v in artifact_dict.items() if k != "signature"}
        payload_bytes = canonical_json_bytes(payload_to_verify)
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()

        if algorithm == "HMAC-SHA256":
            expected_sig = hmac.new(key_bytes, payload_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_sig, signature):
                raise SecurityAuthorizationError(
                    f"Cryptographic signature verification failed for evidence artifact '{clean_ref}'."
                )
        elif algorithm == "Ed25519":
            try:
                from cryptography.hazmat.primitives.asymmetric import ed25519

                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
                raw_sig = bytes.fromhex(signature)
                pub_key.verify(raw_sig, payload_bytes)
            except Exception as e:
                raise SecurityAuthorizationError(
                    f"Ed25519 digital signature verification failed for evidence artifact '{clean_ref}': {e}"
                )
        else:
            raise SecurityAuthorizationError(f"Unsupported algorithm '{algorithm}'")

        # 6. Verify exact entry binding (user_id, job_description_id, source_snapshot_hash)
        entries = artifact_dict.get("entries")
        if not isinstance(entries, list) or len(entries) == 0:
            raise SecurityAuthorizationError(f"Evidence artifact '{clean_ref}' contains no verifiable entries.")

        matched_entry = None
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            e_user = entry.get("user_id")
            e_jd = entry.get("job_description_id")
            e_hash = entry.get("source_snapshot_hash")

            if e_user == user_id and e_jd == job_description_id and e_hash == source_snapshot_hash:
                matched_entry = entry
                break

        if matched_entry is None:
            raise SecurityAuthorizationError(
                f"Evidence artifact '{clean_ref}' does not bind specified (user_id={user_id}, "
                f"job_description_id={job_description_id}, source_snapshot_hash='{source_snapshot_hash}'). "
                "Evidence replay rejected."
            )

        verified_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            "Successfully verified archival evidence '%s' (type: %s, issuer: %s, key: %s) for JD #%d (User #%d)",
            clean_ref,
            clean_type,
            issuer_id,
            key_id,
            job_description_id,
            user_id,
        )

        return VerifiedLegacyEvidence(
            _token=_VERIFICATION_TOKEN,
            evidence_type=clean_type,
            evidence_reference_id=clean_ref,
            evidence_artifact_hash=artifact_hash,
            evidence_payload_hash=payload_hash,
            user_id=user_id,
            job_description_id=job_description_id,
            source_snapshot_hash=source_snapshot_hash,
            migration_boundary=boundary,
            issuer_id=issuer_id,
            key_id=key_id,
            signature_algorithm=algorithm,
            evidence_signature=signature,
            verified_at=verified_at,
            attested_by=clean_principal,
        )

    def verify_attestation(
        self,
        attestation: Any,
        user_id: int,
        job_description_id: int,
        snapshot_hash: str,
    ) -> VerifiedLegacyEvidence:
        """Verifies an existing database attestation record by resolving and verifying its backing artifact."""
        if not attestation:
            raise SecurityAuthorizationError("Attestation is missing or None.")

        # Check identity attributes
        att_user = getattr(attestation, "user_id", None)
        att_jd = getattr(attestation, "job_description_id", None)
        att_hash = getattr(attestation, "source_snapshot_hash", None)
        att_type = getattr(attestation, "evidence_type", None)
        att_ref = getattr(attestation, "evidence_reference_id", None)
        att_by = getattr(attestation, "attested_by", None)

        if not att_by or not str(att_by).strip():
            raise SecurityAuthorizationError("Attestation lacks mandatory 'attested_by' principal.")
        clean_att_by = str(att_by).strip()

        if att_user != user_id:
            raise SecurityAuthorizationError(
                f"Attestation user_id {att_user} does not match requested user_id {user_id}."
            )
        if att_jd != job_description_id:
            raise SecurityAuthorizationError(
                f"Attestation job_description_id {att_jd} does not match requested {job_description_id}."
            )
        if att_hash != snapshot_hash:
            raise SecurityAuthorizationError(
                f"Attestation snapshot_hash '{att_hash}' does not match requested '{snapshot_hash}'."
            )

        # Independently resolve and verify the backing artifact
        verified = self.verify(
            evidence_type=att_type,
            evidence_reference_id=att_ref,
            user_id=user_id,
            job_description_id=job_description_id,
            source_snapshot_hash=snapshot_hash,
            attesting_principal=clean_att_by,
        )

        # Check all cryptographic fields against the independently verified artifact
        stored_art_hash = getattr(attestation, "evidence_artifact_hash", None)
        stored_payload_hash = getattr(attestation, "evidence_payload_hash", None)
        stored_issuer = getattr(attestation, "issuer_id", None)
        stored_key = getattr(attestation, "key_id", None)
        stored_algo = getattr(attestation, "signature_algorithm", None)
        stored_sig = getattr(attestation, "evidence_signature", None)
        stored_boundary = getattr(attestation, "migration_boundary", None)

        # Determine if this is a current-format attestation
        is_current_format = any(
            x is not None
            for x in (
                stored_art_hash,
                stored_payload_hash,
                stored_issuer,
                stored_key,
                stored_algo,
                stored_sig,
                stored_boundary,
                getattr(attestation, "verified_at", None),
            )
        )

        if is_current_format:
            # Current format requires ALL cryptographic audit fields to be present
            if not stored_art_hash:
                raise SecurityAuthorizationError("Current-format attestation lacks mandatory 'evidence_artifact_hash'.")
            if not stored_payload_hash:
                raise SecurityAuthorizationError("Current-format attestation lacks mandatory 'evidence_payload_hash'.")
            if not stored_issuer:
                raise SecurityAuthorizationError("Current-format attestation lacks mandatory 'issuer_id'.")
            if not stored_key:
                raise SecurityAuthorizationError("Current-format attestation lacks mandatory 'key_id'.")
            if not stored_algo:
                raise SecurityAuthorizationError("Current-format attestation lacks mandatory 'signature_algorithm'.")
            if not stored_sig:
                raise SecurityAuthorizationError("Current-format attestation lacks mandatory 'evidence_signature'.")
            if not stored_boundary:
                raise SecurityAuthorizationError("Current-format attestation lacks mandatory 'migration_boundary'.")

        # Compare any present fields (and all fields for current-format) with verified evidence
        if stored_art_hash and stored_art_hash != verified.evidence_artifact_hash:
            raise SecurityAuthorizationError(
                f"Attestation artifact hash mismatch: stored '{stored_art_hash}', verified '{verified.evidence_artifact_hash}'."
            )
        if stored_payload_hash and stored_payload_hash != verified.evidence_payload_hash:
            raise SecurityAuthorizationError(
                f"Attestation payload hash mismatch: stored '{stored_payload_hash}', verified '{verified.evidence_payload_hash}'."
            )
        if stored_issuer and stored_issuer != verified.issuer_id:
            raise SecurityAuthorizationError(
                f"Attestation issuer_id mismatch: stored '{stored_issuer}', verified '{verified.issuer_id}'."
            )
        if stored_key and stored_key != verified.key_id:
            raise SecurityAuthorizationError(
                f"Attestation key_id mismatch: stored '{stored_key}', verified '{verified.key_id}'."
            )
        if stored_algo and stored_algo != verified.signature_algorithm:
            raise SecurityAuthorizationError(
                f"Attestation signature_algorithm mismatch: stored '{stored_algo}', verified '{verified.signature_algorithm}'."
            )
        if stored_sig and stored_sig != verified.evidence_signature:
            raise SecurityAuthorizationError(
                f"Attestation evidence_signature mismatch: stored '{stored_sig}', verified '{verified.evidence_signature}'."
            )
        if stored_boundary and stored_boundary != verified.migration_boundary:
            raise SecurityAuthorizationError(
                f"Attestation migration_boundary mismatch: stored '{stored_boundary}', verified '{verified.migration_boundary}'."
            )

        # Also verify identity bindings on verified vs attestation
        if getattr(attestation, "evidence_type", None) != verified.evidence_type:
            raise SecurityAuthorizationError(
                f"Attestation evidence_type mismatch: stored '{getattr(attestation, 'evidence_type', None)}', verified '{verified.evidence_type}'."
            )
        if getattr(attestation, "evidence_reference_id", None) != verified.evidence_reference_id:
            raise SecurityAuthorizationError(
                f"Attestation evidence_reference_id mismatch: stored '{getattr(attestation, 'evidence_reference_id', None)}', verified '{verified.evidence_reference_id}'."
            )
        if clean_att_by != verified.attested_by:
            raise SecurityAuthorizationError(
                f"Attestation attested_by mismatch: stored '{clean_att_by}', verified '{verified.attested_by}'."
            )

        return verified

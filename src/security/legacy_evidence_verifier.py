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
    """Manages trusted root keys, public keys, and authorized issuers for archival evidence."""

    def __init__(
        self,
        trusted_keys: Optional[Dict[str, Union[str, bytes]]] = None,
        trusted_issuers: Optional[Set[str]] = None,
        revoked_keys: Optional[Set[str]] = None,
        db_manager: Optional[Any] = None,
    ):
        self._lock = threading.RLock()
        self._keys: Dict[str, bytes] = {}
        self._key_algorithms: Dict[str, str] = {}
        self._trusted_issuers: Set[str] = set()
        self._revoked_keys: Set[str] = set()
        self._db_manager = db_manager

        # 1. Load from environment if available
        env_issuers = os.environ.get("LEGACY_EVIDENCE_TRUSTED_ISSUERS")
        if env_issuers:
            try:
                parsed_issuers = json.loads(env_issuers)
                if isinstance(parsed_issuers, list):
                    self._trusted_issuers.update(str(i).strip() for i in parsed_issuers if str(i).strip())
            except Exception as e:
                logger.warning("Failed to parse LEGACY_EVIDENCE_TRUSTED_ISSUERS: %s", e)

        env_keys = os.environ.get("LEGACY_EVIDENCE_TRUSTED_KEYS")
        if env_keys:
            try:
                parsed_keys = json.loads(env_keys)
                if isinstance(parsed_keys, dict):
                    for k_id, val in parsed_keys.items():
                        self.register_trusted_key(k_id, val)
            except Exception as e:
                logger.warning("Failed to parse LEGACY_EVIDENCE_TRUSTED_KEYS: %s", e)

        env_revoked = os.environ.get("LEGACY_EVIDENCE_REVOKED_KEYS")
        if env_revoked:
            try:
                parsed_revoked = json.loads(env_revoked)
                if isinstance(parsed_revoked, list):
                    self._revoked_keys.update(str(k).strip() for k in parsed_revoked if str(k).strip())
            except Exception as e:
                logger.warning("Failed to parse LEGACY_EVIDENCE_REVOKED_KEYS: %s", e)

        # 2. Register caller-supplied parameters
        if trusted_issuers:
            for issuer in trusted_issuers:
                self.register_trusted_issuer(issuer)

        if trusted_keys:
            for k_id, k_val in trusted_keys.items():
                self.register_trusted_key(k_id, k_val)

        if revoked_keys:
            for k_id in revoked_keys:
                self.revoke_key(k_id)

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

    def register_trusted_issuer(self, issuer_id: str) -> None:
        """Registers an authorized evidence issuer identity."""
        if not issuer_id or not isinstance(issuer_id, str) or not issuer_id.strip():
            raise SecurityAuthorizationError(f"Invalid issuer_id '{issuer_id}': cannot be empty.")
        clean_issuer = issuer_id.strip()
        with self._lock:
            self._trusted_issuers.add(clean_issuer)

    def register_trusted_key(
        self,
        key_id: str,
        key_bytes: Union[str, bytes],
        algorithm: str = "HMAC-SHA256",
    ) -> None:
        """Registers a trusted signing key or public key."""
        if not key_id or not isinstance(key_id, str) or not key_id.strip():
            raise SecurityAuthorizationError(f"Invalid key_id '{key_id}': cannot be empty.")
        clean_id = key_id.strip()

        if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise SecurityAuthorizationError(f"Unsupported signature algorithm '{algorithm}'.")

        coerced = self._coerce_bytes(key_bytes)
        if len(coerced) < 32:
            raise SecurityAuthorizationError(
                f"Legacy evidence signing key '{clean_id}' has insufficient entropy "
                f"({len(coerced)} bytes < minimum 32 bytes / 256 bits)."
            )

        with self._lock:
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
    signing_key: Union[str, bytes],
    entries: List[Dict[str, Any]],
    signature_algorithm: str = "HMAC-SHA256",
    migration_boundary: str = "pre_phase_9_1_1",
    issued_at: Optional[str] = None,
) -> Tuple[bytes, Dict[str, Any]]:
    """Helper for authorized migration authorities and tests to produce a canonical signed evidence artifact."""
    if evidence_type not in SUPPORTED_EVIDENCE_TYPES:
        raise ValidationError(f"Unsupported evidence_type '{evidence_type}'")
    if signature_algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ValidationError(f"Unsupported signature_algorithm '{signature_algorithm}'")
    if migration_boundary not in VALID_MIGRATION_BOUNDARIES:
        raise ValidationError(f"Invalid migration_boundary '{migration_boundary}'")

    issued = issued_at or datetime.now(timezone.utc).isoformat()

    payload_to_sign = {
        "evidence_type": evidence_type,
        "evidence_reference_id": evidence_reference_id,
        "issuer_id": issuer_id,
        "key_id": key_id,
        "signature_algorithm": signature_algorithm,
        "migration_boundary": migration_boundary,
        "issued_at": issued,
        "entries": entries,
    }

    payload_bytes = canonical_json_bytes(payload_to_sign)

    # Compute digital signature
    if signature_algorithm == "HMAC-SHA256":
        key_bytes = LegacyEvidenceTrustStore._coerce_bytes(signing_key)
        signature = hmac.new(key_bytes, payload_bytes, hashlib.sha256).hexdigest()
    elif signature_algorithm == "Ed25519":
        from cryptography.hazmat.primitives.asymmetric import ed25519

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
        2. Authorized attesting principal (non-empty, non-candidate user).
        3. Artifact resolution (fails closed if artifact missing).
        4. Artifact SHA-256 hash computation.
        5. Exact metadata equality (type, reference ID, migration boundary).
        6. Trusted issuer identity (not self-attested, authorized in trust store).
        7. Trusted, unrevoked key ID with supported algorithm.
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
        if clean_principal in (f"user_{user_id}", str(user_id), "candidate_user"):
            raise SecurityAuthorizationError(
                f"Candidate user '{clean_principal}' cannot self-attest own source as historical evidence."
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

        boundary = artifact_dict.get("migration_boundary")
        if boundary not in VALID_MIGRATION_BOUNDARIES:
            raise SecurityAuthorizationError(
                f"Evidence artifact asserts invalid or missing historical migration boundary '{boundary}'."
            )

        issuer_id = (artifact_dict.get("issuer_id") or "").strip()
        if not issuer_id:
            raise SecurityAuthorizationError(f"Evidence artifact '{clean_ref}' lacks mandatory issuer_id.")

        if issuer_id in (f"user_{user_id}", str(user_id), "candidate_user"):
            raise SecurityAuthorizationError(
                f"Evidence artifact '{clean_ref}' issuer '{issuer_id}' represents untrusted candidate self-attestation."
            )

        if not self.trust_store.is_issuer_trusted(issuer_id):
            raise SecurityAuthorizationError(
                f"Evidence issuer '{issuer_id}' is unknown or not configured in trust store."
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
        att_by = getattr(attestation, "attested_by", "authorized_migration_principal")

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

        verified = self.verify(
            evidence_type=att_type,
            evidence_reference_id=att_ref,
            user_id=user_id,
            job_description_id=job_description_id,
            source_snapshot_hash=snapshot_hash,
            attesting_principal=att_by,
        )

        # Check stored hashes if present on attestation model
        stored_art_hash = getattr(attestation, "evidence_artifact_hash", None)
        if stored_art_hash and stored_art_hash != verified.evidence_artifact_hash:
            raise SecurityAuthorizationError(
                f"Attestation artifact hash mismatch: stored '{stored_art_hash}', verified '{verified.evidence_artifact_hash}'."
            )

        return verified

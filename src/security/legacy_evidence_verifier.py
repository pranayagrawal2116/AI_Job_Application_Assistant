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
import base64
from contextlib import contextmanager
import contextvars
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import threading
import types
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple, Union
import uuid

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

# Default authorized attesting principals for system migration (Phase 9.1.2.8 Part B: empty by default)
DEFAULT_AUTHORIZED_ATTESTING_PRINCIPALS: frozenset[str] = frozenset()

# Private sentinel tokens preventing arbitrary external instantiation
_VERIFICATION_TOKEN = object()
_AUTH_TOKEN = object()


def resolve_app_env() -> str:
    """Authoritatively resolves and validates the application execution environment.

    Contract (Phase 9.1.2.9 Section 5.1):
    - production / prod -> 'production' (Ed25519 asymmetric only)
    - staging -> 'staging' (Ed25519 asymmetric only)
    - qa -> 'qa' (Ed25519 asymmetric only)
    - development / dev -> 'development' (Permissive policy permitted)
    - test -> 'test' (Permissive policy permitted)
    - missing / empty / whitespace / unknown -> raises SecurityAuthorizationError (fails closed)
    """
    raw_env = os.environ.get("APP_ENV")
    if raw_env is None:
        raise SecurityAuthorizationError(
            "APP_ENV environment variable is missing. Application security policy fails closed."
        )
    clean_env = raw_env.strip()
    if not clean_env:
        raise SecurityAuthorizationError(
            "APP_ENV environment variable is empty or whitespace. Application security policy fails closed."
        )
    normalized = clean_env.lower()
    if normalized in ("production", "prod"):
        return "production"
    if normalized == "staging":
        return "staging"
    if normalized == "qa":
        return "qa"
    if normalized in ("development", "dev"):
        return "development"
    if normalized == "test":
        return "test"
    raise SecurityAuthorizationError(
        f"Unrecognized or untrusted APP_ENV '{raw_env}'. Application security policy fails closed."
    )


# Central injectable UTC clock provider (Phase 9.1.2.12 Part F, Phase 9.1.2.13 Part A, Phase 9.1.2.14 Part D)
_CLOCK_VAR: contextvars.ContextVar[Optional[Callable[[], datetime]]] = contextvars.ContextVar(
    "_CLOCK_VAR", default=None
)


def get_current_utc_time() -> datetime:
    """Returns current UTC datetime from configured context clock provider or system clock."""
    provider = _CLOCK_VAR.get()
    if provider is not None:
        val = provider()
        if not isinstance(val, datetime):
            raise SecurityAuthorizationError(
                f"Configured clock provider returned invalid type '{type(val).__name__}', expected datetime."
            )
        if val.tzinfo is None:
            raise SecurityAuthorizationError(
                "Configured clock provider returned timezone-naive datetime."
            )
        return val.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def set_test_clock(clock: Optional[Callable[[], datetime]]) -> None:
    """Configures a custom UTC clock provider for deterministic testing.

    Security Invariants (Phase 9.1.2.13 / Phase 9.1.2.14):
    1. Uses authoritative resolve_app_env() for environment resolution.
    2. Prohibits clock injection in 'production', 'prod', 'staging', 'qa', or unknown environments.
    3. Fails closed if APP_ENV is missing, empty, whitespace, or invalid.
    4. Permits non-None clock injection ONLY in recognized non-production environments ('development', 'dev', 'test').
    5. Always permits clearing an existing test override (clock=None) regardless of environment.
    6. Uses ContextVar exclusively to prevent cross-thread or cross-context clock contamination.
    """
    if clock is not None:
        env = resolve_app_env()
        if env in ("production", "staging", "qa"):
            raise SecurityAuthorizationError(
                f"Clock injection is strictly prohibited in production-like environment '{env}'."
            )
        if env not in ("development", "test"):
            raise SecurityAuthorizationError(
                f"Clock injection is not permitted in environment '{env}'."
            )
    _CLOCK_VAR.set(clock)


@contextmanager
def frozen_utc_clock(target_time: datetime) -> Generator[None, None, None]:
    """Context manager for freezing UTC clock during tests with automatic context restoration.

    Security Invariants (Phase 9.1.2.13 / Phase 9.1.2.14):
    - Target time must be an explicit timezone-aware datetime instance.
    - Enforces resolve_app_env() policy before setting the clock.
    - ContextVar token reset guarantees reliable restoration even across nested contexts or exceptions.
    """
    if not isinstance(target_time, datetime):
        raise SecurityAuthorizationError(
            f"Target time must be a datetime instance, got '{type(target_time).__name__}'."
        )
    if target_time.tzinfo is None:
        raise SecurityAuthorizationError(
            "Target time must be a timezone-aware datetime."
        )
    target_utc = target_time.astimezone(timezone.utc)
    env = resolve_app_env()
    if env in ("production", "staging", "qa"):
        raise SecurityAuthorizationError(
            f"Clock injection is strictly prohibited in production-like environment '{env}'."
        )
    if env not in ("development", "test"):
        raise SecurityAuthorizationError(
            f"Clock injection is not permitted in environment '{env}'."
        )
    token = _CLOCK_VAR.set(lambda: target_utc)
    try:
        yield
    finally:
        _CLOCK_VAR.reset(token)


@dataclass(frozen=True)
class _IssuedCredentialRecord:
    """Authoritative immutable issuance record for an authenticated migration credential."""

    credential_id: str
    principal_id: str
    credential_key_id: str
    issuer: str
    audience: str
    scopes: Tuple[str, ...]
    principal_type: str
    issued_at: datetime
    expires_at: datetime
    provider_instance_id: str
    signature_algorithm: str

    def __getitem__(self, key: str) -> Any:
        if not hasattr(self, key):
            raise KeyError(key)
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


@dataclass(frozen=True)
class AuthenticatedMigrationPrincipal:
    """Represents a verified service identity authorized to verify and attest historical legacy evidence.

    Security Invariant (Phase 9.1.2.11):
    - Cannot be directly constructed by callers or manufactured with unverified Boolean flags.
    - Can ONLY be issued by ServiceAuthenticationProvider after authenticating genuine credentials.
    - Strictly bound to issuing ServiceAuthenticationProvider instance via _provider_instance_id and _provider_sentinel.
    - Must possess non-empty credential_id and credential_key_id matching authoritative issuance record.
    - Strictly bound to 'legacy_migration' authorization scope (no generic 'all' super-scope).
    - Principal type must be strictly 'service'.
    - Must have explicit issued_at and expires_at; credential lifetime enforced.
    - Metadata is defensively copied and immutable.
    - Candidate users are strictly prohibited from holding this context.
    """

    _token: Any = None
    _provider_instance_id: str = ""
    _provider_sentinel: Any = None
    principal_id: str = ""
    issuer: str = "internal_service_authority"
    audience: str = "legacy_migration"
    scopes: Tuple[str, ...] = ("legacy_migration",)
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    credential_id: Optional[str] = None
    credential_key_id: Optional[str] = None
    principal_type: str = "service"
    signature_algorithm: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self._token is not _AUTH_TOKEN:
            raise SecurityAuthorizationError(
                "AuthenticatedMigrationPrincipal cannot be directly instantiated or manufactured. "
                "Identity must be verified through ServiceAuthenticationProvider."
            )
        if not self.principal_id or not isinstance(self.principal_id, str) or not self.principal_id.strip():
            raise ValidationError("AuthenticatedMigrationPrincipal principal_id cannot be empty or whitespace.")
        clean_id = self.principal_id.strip()
        if clean_id in ("candidate_user",) or clean_id.startswith("user_") or clean_id.startswith("candidate_"):
            raise SecurityAuthorizationError(f"Candidate user '{clean_id}' cannot be an authenticated migration principal.")
        if self.principal_type != "service":
            raise SecurityAuthorizationError(
                f"Invalid principal_type '{self.principal_type}'. Only 'service' principal_type is authorized for migration principals."
            )
        if "legacy_migration" not in self.scopes:
            raise SecurityAuthorizationError(f"Principal '{clean_id}' lacks legacy_migration authorization scope.")

        now_utc = get_current_utc_time()
        if self.expires_at is None:
            raise SecurityAuthorizationError(f"Authenticated migration principal '{clean_id}' missing mandatory expiration timestamp.")
        if isinstance(self.expires_at, bool):
            raise SecurityAuthorizationError(f"Invalid 'expires_at' for '{clean_id}': must be datetime.")
        if self.expires_at <= now_utc:
            raise SecurityAuthorizationError(f"Principal credential for '{clean_id}' has expired.")
        if self.issued_at is None:
            raise SecurityAuthorizationError(f"Authenticated migration principal '{clean_id}' missing mandatory issued_at timestamp.")
        if isinstance(self.issued_at, bool):
            raise SecurityAuthorizationError(f"Invalid 'issued_at' for '{clean_id}': must be datetime.")
        if self.issued_at > now_utc + timedelta(seconds=60):
            raise SecurityAuthorizationError(f"Principal credential for '{clean_id}' issued in the future.")
        if self.expires_at <= self.issued_at:
            raise SecurityAuthorizationError(f"Principal credential for '{clean_id}' has non-positive lifetime (exp <= iat).")

        if not self.credential_id or not isinstance(self.credential_id, str) or not self.credential_id.strip():
            raise SecurityAuthorizationError("Authenticated migration principal missing mandatory credential_id.")
        if not self.credential_key_id or not isinstance(self.credential_key_id, str) or not self.credential_key_id.strip():
            raise SecurityAuthorizationError("Authenticated migration principal missing mandatory credential_key_id.")

        if not self.signature_algorithm or not isinstance(self.signature_algorithm, str) or not self.signature_algorithm.strip():
            raise SecurityAuthorizationError("Authenticated migration principal missing mandatory signature_algorithm.")
        clean_algo = self.signature_algorithm.strip()
        if clean_algo not in ("EdDSA", "Ed25519", "HS256", "HMAC-SHA256"):
            raise SecurityAuthorizationError(f"Unsupported signature algorithm '{clean_algo}' for authenticated migration principal.")
        app_env = resolve_app_env()
        if app_env in ("production", "staging", "qa") and clean_algo in ("HS256", "HMAC-SHA256"):
            raise SecurityAuthorizationError(
                f"HMAC signature algorithm '{clean_algo}' is strictly prohibited in '{app_env}'. Production requires EdDSA / Ed25519."
            )

        if isinstance(self.metadata, dict):
            object.__setattr__(self, "metadata", types.MappingProxyType(dict(self.metadata)))

    @property
    def is_authenticated(self) -> bool:
        """Always True because instances can only be minted by ServiceAuthenticationProvider."""
        return True

    @property
    def is_expired(self) -> bool:
        """Returns True if the principal credential has reached or passed its expiration timestamp."""
        if self.expires_at is None:
            return True
        return self.expires_at <= get_current_utc_time()

    @property
    def is_revoked(self) -> bool:
        """State is checked at verification time by verifier and trust store."""
        return False

    @property
    def authorization_scope(self) -> str:
        return "legacy_migration"


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
    # Authenticated context provenance (Phase 9.1.2.11):
    attesting_principal_id: str = ""
    provider_instance_id: str = ""
    credential_id: str = ""
    credential_key_id: str = ""
    issuer: str = ""
    audience: str = ""
    scopes: Tuple[str, ...] = field(default_factory=tuple)
    issued_at: str = ""
    expires_at: str = ""

    def __post_init__(self) -> None:
        if self._token is not _VERIFICATION_TOKEN:
            raise SecurityAuthorizationError(
                "VerifiedLegacyEvidence cannot be instantiated directly. "
                "Must be produced by LegacyEvidenceVerifier.verify()."
            )


class ServiceAuthenticationProvider:
    """Authenticates internal service credentials and issues AuthenticatedMigrationPrincipal instances.

    Security Boundary (Phase 9.1.2.10):
    - Validates cryptographic signatures (Ed25519 or HMAC-SHA256 based on policy).
    - In production, strictly enforces Ed25519 signatures and rejects HMAC.
    - Strictly binds issued AuthenticatedMigrationPrincipal to provider instance via unique sentinel and ID.
    - Validates trusted issuer, intended audience, principal identity, scopes, and expiration.
    - Strict JWT claims: typ == 'JWT', reject crit, mandatory numeric iat and exp, exp > iat, max 24h lifetime.
    - Enforces key-algorithm binding and key immutability.
    - Enforces revocation checks against DatabaseManager and trust store.
    - Rejects candidate identities, expired credentials, invalid signatures, wrong scopes, non-service principal types.
    """

    DEFAULT_AUDIENCE = "legacy_migration"

    def __init__(
        self,
        trusted_keys: Optional[Dict[str, Union[str, bytes, Any]]] = None,
        trusted_issuers: Optional[Set[str]] = None,
        expected_audience: str = "legacy_migration",
        db_manager: Optional[Any] = None,
        trust_store: Optional[Any] = None,
    ):
        self.app_env = resolve_app_env()
        self.expected_audience = expected_audience
        self.db_manager = db_manager
        self.trust_store = trust_store
        self._lock = threading.RLock()
        self._provider_id = f"sap_{uuid.uuid4().hex}"
        self._provider_sentinel = object()
        self._trusted_keys: Dict[str, Tuple[bytes, str]] = {}
        self._trusted_issuers: Set[str] = set()
        self._issued_credentials: Dict[str, _IssuedCredentialRecord] = {}

        if self.app_env in ("production", "staging", "qa") and self.db_manager is None:
            raise SecurityAuthorizationError(
                f"Authoritative DatabaseManager is mandatory for ServiceAuthenticationProvider in '{self.app_env}'."
            )

        if trusted_issuers:
            for iss in trusted_issuers:
                clean_iss = (iss or "").strip()
                if clean_iss:
                    self._trusted_issuers.add(clean_iss)

        if trusted_keys:
            staged: Dict[str, Tuple[bytes, str]] = {}
            for k_id, k_val in trusted_keys.items():
                clean_id = (k_id or "").strip()
                if not clean_id:
                    raise SecurityAuthorizationError("Service authentication key ID cannot be empty or whitespace.")

                if self.db_manager and hasattr(self.db_manager, "is_key_revoked") and self.db_manager.is_key_revoked(clean_id):
                    raise KeyRevokedError(clean_id)
                if self.trust_store and hasattr(self.trust_store, "is_key_revoked") and self.trust_store.is_key_revoked(clean_id):
                    raise KeyRevokedError(clean_id)

                if isinstance(k_val, dict):
                    k_bytes = k_val.get("key") or k_val.get("key_bytes") or b""
                    k_algo = k_val.get("algorithm") or "HMAC-SHA256"
                else:
                    k_bytes = k_val
                    k_algo = "Ed25519" if len(self._coerce_bytes(k_val)) == 32 and self.app_env in ("production", "staging", "qa") else "HMAC-SHA256"

                if k_algo not in ("Ed25519", "EdDSA", "HMAC-SHA256", "HS256"):
                    raise SecurityAuthorizationError(f"Unsupported service signing algorithm '{k_algo}'.")

                if self.app_env in ("production", "staging", "qa") and k_algo in ("HMAC-SHA256", "HS256"):
                    raise SecurityAuthorizationError(
                        f"HMAC service signing keys are strictly prohibited in '{self.app_env}'. Production requires asymmetric Ed25519 keys."
                    )

                coerced = self._coerce_bytes(k_bytes)
                if k_algo in ("Ed25519", "EdDSA"):
                    from cryptography.hazmat.primitives.asymmetric import ed25519
                    if len(coerced) != 32:
                        raise SecurityAuthorizationError(f"Ed25519 public key must be exactly 32 bytes (got {len(coerced)} bytes).")
                    try:
                        _ = ed25519.Ed25519PublicKey.from_public_bytes(coerced)
                    except Exception as e:
                        raise SecurityAuthorizationError(f"Invalid Ed25519 public key '{clean_id}': {e}")
                    norm_algo = "Ed25519"
                else:
                    if len(coerced) < 32:
                        raise SecurityAuthorizationError(f"HMAC secret must have at least 32 bytes of entropy (got {len(coerced)}).")
                    norm_algo = "HMAC-SHA256"

                staged[clean_id] = (coerced, norm_algo)
            self._trusted_keys.update(staged)

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

    @staticmethod
    def _b64url_decode(input_str: str) -> bytes:
        rem = len(input_str) % 4
        if rem > 0:
            input_str += "=" * (4 - rem)
        return base64.urlsafe_b64decode(input_str.encode("utf-8"))

    def register_trusted_key(
        self,
        key_id: str,
        key_data: Union[str, bytes, Any],
        algorithm: Optional[str] = None,
    ) -> None:
        clean_id = (key_id or "").strip()
        if not clean_id:
            raise SecurityAuthorizationError("Service authentication key ID cannot be empty or whitespace.")

        if self.db_manager and hasattr(self.db_manager, "is_key_revoked"):
            if self.db_manager.is_key_revoked(clean_id):
                raise KeyRevokedError(clean_id)

        if self.trust_store and hasattr(self.trust_store, "is_key_revoked"):
            if self.trust_store.is_key_revoked(clean_id):
                raise KeyRevokedError(clean_id)

        if isinstance(key_data, dict):
            k_bytes = key_data.get("key") or key_data.get("key_bytes") or b""
            k_algo = key_data.get("algorithm") or algorithm or "HMAC-SHA256"
        else:
            k_bytes = key_data
            k_algo = algorithm or ("Ed25519" if len(self._coerce_bytes(key_data)) == 32 and self.app_env in ("production", "staging", "qa") else "HMAC-SHA256")

        if k_algo not in ("Ed25519", "EdDSA", "HMAC-SHA256", "HS256"):
            raise SecurityAuthorizationError(f"Unsupported service signing algorithm '{k_algo}'.")

        if self.app_env in ("production", "staging", "qa") and k_algo in ("HMAC-SHA256", "HS256"):
            raise SecurityAuthorizationError(
                f"HMAC service signing keys are strictly prohibited in '{self.app_env}'. Production requires asymmetric Ed25519 keys."
            )

        coerced = self._coerce_bytes(k_bytes)
        if k_algo in ("Ed25519", "EdDSA"):
            from cryptography.hazmat.primitives.asymmetric import ed25519
            if len(coerced) != 32:
                raise SecurityAuthorizationError(f"Ed25519 public key must be exactly 32 bytes (got {len(coerced)} bytes).")
            try:
                _ = ed25519.Ed25519PublicKey.from_public_bytes(coerced)
            except Exception as e:
                raise SecurityAuthorizationError(f"Invalid Ed25519 public key '{clean_id}': {e}")
            norm_algo = "Ed25519"
        else:
            if len(coerced) < 32:
                raise SecurityAuthorizationError(f"HMAC secret must have at least 32 bytes of entropy (got {len(coerced)}).")
            norm_algo = "HMAC-SHA256"

        with self._lock:
            if clean_id in self._trusted_keys:
                existing_bytes, existing_algo = self._trusted_keys[clean_id]
                if existing_bytes == coerced and existing_algo == norm_algo:
                    return
                if existing_bytes != coerced:
                    raise SecurityAuthorizationError(
                        f"Trusted service authentication key ID '{clean_id}' already registered with different key material. Immutability violation."
                    )
                if existing_algo != norm_algo:
                    raise SecurityAuthorizationError(
                        f"Trusted service authentication key ID '{clean_id}' already registered with different algorithm ('{existing_algo}' != '{norm_algo}'). Immutability violation."
                    )

            self._trusted_keys[clean_id] = (coerced, norm_algo)

    def authenticate(self, credential: Any) -> AuthenticatedMigrationPrincipal:
        """Verifies a service credential token and returns an authentic AuthenticatedMigrationPrincipal."""
        if credential is None or not credential:
            raise SecurityAuthorizationError("Missing service credential: credential is required.")

        if not isinstance(credential, str) or not credential.strip():
            raise SecurityAuthorizationError("Invalid service credential: must be a non-empty string.")

        parts = credential.strip().split(".")
        if len(parts) != 3:
            raise SecurityAuthorizationError(
                f"Invalid service credential format: expected 3 dot-separated segments, got {len(parts)}."
            )

        header_b64, payload_b64, sig_b64 = parts

        try:
            header_json = self._b64url_decode(header_b64).decode("utf-8")
            header = json.loads(header_json)
        except Exception as e:
            raise SecurityAuthorizationError(f"Invalid service credential header: {e}")

        if not isinstance(header, dict):
            raise SecurityAuthorizationError("Invalid service credential header: must be a JSON object.")

        if header.get("typ") != "JWT":
            raise SecurityAuthorizationError("Service credential header must specify 'typ': 'JWT'.")

        if "crit" in header:
            raise SecurityAuthorizationError("Critical header parameters ('crit') are not supported.")

        try:
            payload_json = self._b64url_decode(payload_b64).decode("utf-8")
            payload = json.loads(payload_json)
        except Exception as e:
            raise SecurityAuthorizationError(f"Invalid service credential payload: {e}")

        if not isinstance(payload, dict):
            raise SecurityAuthorizationError("Invalid service credential payload: must be a JSON object.")

        try:
            signature_bytes = self._b64url_decode(sig_b64)
        except Exception as e:
            raise SecurityAuthorizationError(f"Invalid service credential signature encoding: {e}")

        alg = header.get("alg")
        if not alg or alg == "none":
            raise SecurityAuthorizationError("Unsigned service credentials (alg='none') are strictly prohibited.")

        kid = header.get("kid")
        if not kid or not str(kid).strip():
            raise SecurityAuthorizationError("Service credential header missing mandatory 'kid'.")
        clean_kid = str(kid).strip()

        with self._lock:
            if clean_kid not in self._trusted_keys:
                raise SecurityAuthorizationError(f"Unknown service signing key ID '{clean_kid}'.")
            key_bytes, key_algo = self._trusted_keys[clean_kid]

        if self.db_manager and hasattr(self.db_manager, "is_key_revoked"):
            if self.db_manager.is_key_revoked(clean_kid):
                raise KeyRevokedError(clean_kid)

        if self.trust_store and hasattr(self.trust_store, "is_key_revoked"):
            if self.trust_store.is_key_revoked(clean_kid):
                raise KeyRevokedError(clean_kid)

        # Strict algorithm-to-key binding (prevents algorithm confusion)
        if key_algo == "Ed25519":
            if alg not in ("EdDSA", "Ed25519"):
                raise SecurityAuthorizationError(
                    f"Algorithm mismatch: key '{clean_kid}' is registered as Ed25519, but credential header specifies '{alg}'."
                )
        elif key_algo == "HMAC-SHA256":
            if alg not in ("HS256", "HMAC-SHA256"):
                raise SecurityAuthorizationError(
                    f"Algorithm mismatch: key '{clean_kid}' is registered as HMAC-SHA256, but credential header specifies '{alg}'."
                )
        else:
            raise SecurityAuthorizationError(f"Unsupported key algorithm '{key_algo}'.")

        if self.app_env in ("production", "staging", "qa") and alg in ("HS256", "HMAC-SHA256"):
            raise SecurityAuthorizationError(
                f"HMAC service credentials are prohibited under '{self.app_env}' policy. Production requires EdDSA / Ed25519."
            )

        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        if alg in ("HS256", "HMAC-SHA256"):
            expected_sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(expected_sig, signature_bytes):
                raise SecurityAuthorizationError("Invalid service credential signature.")
        elif alg in ("EdDSA", "Ed25519"):
            from cryptography.hazmat.primitives.asymmetric import ed25519
            try:
                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
                pub_key.verify(signature_bytes, signing_input)
            except Exception:
                raise SecurityAuthorizationError("Invalid service credential signature.")
        else:
            raise SecurityAuthorizationError(f"Unsupported credential algorithm '{alg}'.")

        iss = payload.get("iss")
        if not iss or not isinstance(iss, str) or not iss.strip():
            raise SecurityAuthorizationError("Service credential payload missing mandatory 'iss' claim.")
        clean_iss = iss.strip()
        with self._lock:
            if clean_iss not in self._trusted_issuers:
                raise SecurityAuthorizationError(f"Untrusted service credential issuer '{clean_iss}'.")

        aud = payload.get("aud")
        if aud is None or isinstance(aud, bool):
            raise SecurityAuthorizationError("Service credential payload missing mandatory 'aud' claim.")
        if isinstance(aud, str):
            clean_aud_val = aud.strip()
            if not clean_aud_val:
                raise SecurityAuthorizationError("Service credential 'aud' cannot be empty or whitespace.")
            aud_list = [clean_aud_val]
        elif isinstance(aud, (list, tuple)):
            if len(aud) == 0:
                raise SecurityAuthorizationError("Service credential 'aud' list cannot be empty.")
            aud_list = []
            for item in aud:
                if isinstance(item, bool) or not isinstance(item, str):
                    raise SecurityAuthorizationError("Invalid 'aud' item in service credential: all items must be strings.")
                clean_item = item.strip()
                if not clean_item:
                    raise SecurityAuthorizationError("Invalid 'aud' item in service credential: empty string is prohibited.")
                aud_list.append(clean_item)
        else:
            raise SecurityAuthorizationError("Service credential 'aud' must be a non-empty string or list of non-empty strings.")
        if self.expected_audience not in aud_list:
            raise SecurityAuthorizationError(
                f"Service credential audience '{aud}' does not match expected audience '{self.expected_audience}'."
            )

        sub = payload.get("sub") or payload.get("principal_id")
        if not sub or not isinstance(sub, str) or not sub.strip():
            raise SecurityAuthorizationError("Service credential payload missing mandatory 'sub' claim.")
        clean_sub = sub.strip()

        if clean_sub in ("candidate_user",) or clean_sub.startswith("user_") or clean_sub.startswith("candidate_"):
            raise SecurityAuthorizationError(f"Candidate user '{clean_sub}' cannot be an authenticated service principal.")

        ptype = payload.get("principal_type")
        if ptype != "service":
            raise SecurityAuthorizationError(f"Invalid principal_type '{ptype}' in service credential: strictly 'service' required.")

        raw_scopes = payload.get("scope") if "scope" in payload else payload.get("scopes")
        if raw_scopes is None or isinstance(raw_scopes, bool):
            raise SecurityAuthorizationError("Service credential payload missing mandatory 'scope' claim.")
        if isinstance(raw_scopes, str):
            clean_scope_str = raw_scopes.strip()
            if not clean_scope_str:
                raise SecurityAuthorizationError("Service credential 'scope' claim cannot be empty.")
            scopes_tokens = clean_scope_str.split()
            if not scopes_tokens:
                raise SecurityAuthorizationError("Service credential 'scope' claim contains no scopes.")
            scopes = tuple(scopes_tokens)
        elif isinstance(raw_scopes, (list, tuple)):
            if len(raw_scopes) == 0:
                raise SecurityAuthorizationError("Service credential 'scope' list cannot be empty.")
            parsed_scopes = []
            for s in raw_scopes:
                if isinstance(s, bool) or not isinstance(s, str):
                    raise SecurityAuthorizationError("Invalid 'scope' item in service credential: all items must be strings.")
                clean_s = s.strip()
                if not clean_s:
                    raise SecurityAuthorizationError("Invalid 'scope' item in service credential: empty scope entry is prohibited.")
                parsed_scopes.append(clean_s)
            scopes = tuple(parsed_scopes)
        else:
            raise SecurityAuthorizationError("Invalid 'scope' claim format in service credential: must be string or list of strings.")
        if "legacy_migration" not in scopes:
            raise SecurityAuthorizationError("Service credential lacks mandatory 'legacy_migration' authorization scope.")

        now_ts = get_current_utc_time().timestamp()

        iat = payload.get("iat")
        if iat is None:
            raise SecurityAuthorizationError("Service credential payload missing mandatory 'iat' claim.")
        if isinstance(iat, bool) or not isinstance(iat, (int, float)) or math.isnan(iat) or math.isinf(iat):
            raise SecurityAuthorizationError("Invalid 'iat' timestamp in service credential: must be a finite numeric value.")
        iat_float = float(iat)
        if iat_float < 0 or iat_float > 253402300799:
            raise SecurityAuthorizationError("Invalid 'iat' timestamp in service credential: out of range.")
        if iat_float > now_ts + 60:
            raise SecurityAuthorizationError("Service credential issued in the future.")
        issued_at_dt = datetime.fromtimestamp(iat_float, tz=timezone.utc)

        exp = payload.get("exp")
        if exp is None:
            raise SecurityAuthorizationError("Service credential payload missing mandatory 'exp' claim.")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or math.isnan(exp) or math.isinf(exp):
            raise SecurityAuthorizationError("Invalid 'exp' timestamp in service credential: must be a finite numeric value.")
        exp_float = float(exp)
        if exp_float < 0 or exp_float > 253402300799:
            raise SecurityAuthorizationError("Invalid 'exp' timestamp in service credential: out of range.")
        if exp_float <= now_ts:
            raise SecurityAuthorizationError(f"Service credential has expired (exp={exp_float}).")
        if exp_float <= iat_float:
            raise SecurityAuthorizationError("Invalid service credential: exp must be greater than iat.")
        if exp_float - iat_float > 86400:
            raise SecurityAuthorizationError("Service credential lifetime exceeds maximum allowed threshold (24 hours).")
        expires_at_dt = datetime.fromtimestamp(exp_float, tz=timezone.utc)

        nbf = payload.get("nbf")
        if nbf is not None:
            if isinstance(nbf, bool) or not isinstance(nbf, (int, float)) or math.isnan(nbf) or math.isinf(nbf):
                raise SecurityAuthorizationError("Invalid 'nbf' timestamp in service credential: must be a finite numeric value.")
            nbf_float = float(nbf)
            if now_ts < nbf_float - 60:
                raise SecurityAuthorizationError("Service credential is not yet valid (nbf).")

        if self.db_manager and hasattr(self.db_manager, "is_principal_revoked"):
            if self.db_manager.is_principal_revoked(clean_sub):
                raise SecurityAuthorizationError(f"Migration principal '{clean_sub}' has been revoked.")

        if self.trust_store and hasattr(self.trust_store, "is_principal_revoked"):
            if self.trust_store.is_principal_revoked(clean_sub):
                raise SecurityAuthorizationError(f"Migration principal '{clean_sub}' has been revoked.")

        jti = payload.get("jti")
        if jti is not None:
            if isinstance(jti, bool) or not isinstance(jti, str):
                raise SecurityAuthorizationError("Invalid 'jti' in service credential: must be a non-empty string.")
            token_jti = jti.strip()
            if not token_jti:
                raise SecurityAuthorizationError("Invalid 'jti' in service credential: cannot be empty or whitespace.")
        else:
            token_jti = f"jti_{secrets.token_hex(16)}"

        with self._lock:
            if token_jti in self._issued_credentials:
                existing = self._issued_credentials[token_jti]
                if (
                    existing.principal_id != clean_sub
                    or existing.credential_key_id != clean_kid
                    or existing.issuer != clean_iss
                    or existing.audience != self.expected_audience
                    or existing.scopes != scopes
                    or existing.principal_type != ptype
                    or existing.issued_at != issued_at_dt
                    or existing.expires_at != expires_at_dt
                    or existing.provider_instance_id != self._provider_id
                    or existing.signature_algorithm != alg
                ):
                    raise SecurityAuthorizationError(
                        f"Duplicate credential identifier '{token_jti}' with conflicting claims is rejected."
                    )
            else:
                self._issued_credentials[token_jti] = _IssuedCredentialRecord(
                    credential_id=token_jti,
                    principal_id=clean_sub,
                    credential_key_id=clean_kid,
                    issuer=clean_iss,
                    audience=self.expected_audience,
                    scopes=scopes,
                    principal_type=ptype,
                    issued_at=issued_at_dt,
                    expires_at=expires_at_dt,
                    provider_instance_id=self._provider_id,
                    signature_algorithm=alg,
                )

        return AuthenticatedMigrationPrincipal(
            _token=_AUTH_TOKEN,
            _provider_instance_id=self._provider_id,
            _provider_sentinel=self._provider_sentinel,
            principal_id=clean_sub,
            issuer=clean_iss,
            audience=self.expected_audience,
            scopes=scopes,
            issued_at=issued_at_dt,
            expires_at=expires_at_dt,
            credential_id=token_jti,
            credential_key_id=clean_kid,
            principal_type=ptype,
            signature_algorithm=alg,
        )

    def validate_principal(self, principal: Any, cursor: Optional[Any] = None) -> None:
        """Validates that an AuthenticatedMigrationPrincipal was minted by this exact provider instance and remains valid.

        Enforces:
        1. Correct type (AuthenticatedMigrationPrincipal) and non-tampered _token.
        2. Provider instance binding (_provider_instance_id == self._provider_id and _provider_sentinel is self._provider_sentinel).
        3. Mandatory non-empty credential_id and credential_key_id.
        4. Complete, unconditional verification against authoritative issuance record in _issued_credentials.
        5. Credential lifetime (expires_at > now_utc, issued_at <= now_utc + 60s).
        6. Principal identity non-empty, non-candidate, not revoked in DB or trust store.
        7. Signing key used remains registered in this provider and not revoked.
        8. Authorized scope strictly 'legacy_migration' and principal_type == 'service'.
        """
        if not isinstance(principal, AuthenticatedMigrationPrincipal):
            raise SecurityAuthorizationError(
                f"Invalid principal context: expected AuthenticatedMigrationPrincipal, got '{type(principal).__name__}'."
            )
        if principal._token is not _AUTH_TOKEN:
            raise SecurityAuthorizationError("Tampered AuthenticatedMigrationPrincipal token.")
        if (
            principal._provider_instance_id != self._provider_id
            or principal._provider_sentinel is not self._provider_sentinel
        ):
            raise SecurityAuthorizationError(
                "Principal context was minted by an unauthorized or independent ServiceAuthenticationProvider instance. "
                "Cross-provider credential reuse is strictly prohibited."
            )

        if not principal.credential_id or not isinstance(principal.credential_id, str) or not principal.credential_id.strip():
            raise SecurityAuthorizationError("Principal missing mandatory credential_id.")

        if not principal.credential_key_id or not isinstance(principal.credential_key_id, str) or not principal.credential_key_id.strip():
            raise SecurityAuthorizationError("Principal missing mandatory credential_key_id.")

        clean_cred_id = principal.credential_id.strip()
        clean_key_id = principal.credential_key_id.strip()

        if not principal.signature_algorithm or not isinstance(principal.signature_algorithm, str) or not principal.signature_algorithm.strip():
            raise SecurityAuthorizationError("Principal missing mandatory signature_algorithm.")
        clean_principal_algo = principal.signature_algorithm.strip()

        with self._lock:
            record = self._issued_credentials.get(clean_cred_id)
            if record is None:
                raise SecurityAuthorizationError(
                    f"Principal credential ID '{clean_cred_id}' is not registered or was never issued by this provider."
                )

            # Unconditional comparison of all security-relevant claims against authoritative issuance record
            if principal.principal_id != record.principal_id:
                raise SecurityAuthorizationError("Tampered principal context claims do not match issued record (principal_id mismatch).")
            if clean_key_id != record.credential_key_id:
                raise SecurityAuthorizationError("Tampered principal context claims do not match issued record (credential_key_id mismatch).")
            if principal.issuer != record.issuer:
                raise SecurityAuthorizationError("Tampered principal context claims do not match issued record (issuer mismatch).")
            if principal.audience != record.audience:
                raise SecurityAuthorizationError("Tampered principal context claims do not match issued record (audience mismatch).")
            if tuple(principal.scopes) != tuple(record.scopes):
                raise SecurityAuthorizationError("Tampered principal context claims do not match issued record (scopes mismatch).")
            if principal.principal_type != record.principal_type or principal.principal_type != "service":
                raise SecurityAuthorizationError("Tampered principal context claims do not match issued record (principal_type mismatch).")
            if principal.issued_at != record.issued_at:
                raise SecurityAuthorizationError("Tampered principal context claims do not match issued record (issued_at mismatch).")
            if principal.expires_at != record.expires_at:
                raise SecurityAuthorizationError("Tampered principal context claims do not match issued record (expires_at mismatch).")
            if principal._provider_instance_id != record.provider_instance_id:
                raise SecurityAuthorizationError("Tampered principal context claims do not match issued record (provider_instance_id mismatch).")
            if clean_principal_algo != record.signature_algorithm:
                raise SecurityAuthorizationError("Tampered principal context claims do not match issued record (signature_algorithm mismatch).")

        clean_sub = principal.principal_id.strip()
        if not clean_sub:
            raise SecurityAuthorizationError("Principal ID cannot be empty.")
        if clean_sub in ("candidate_user",) or clean_sub.startswith("user_") or clean_sub.startswith("candidate_"):
            raise SecurityAuthorizationError(f"Candidate user '{clean_sub}' cannot be an authenticated service principal.")

        if "legacy_migration" not in principal.scopes:
            raise SecurityAuthorizationError(f"Principal '{clean_sub}' lacks 'legacy_migration' authorization scope.")

        now_utc = get_current_utc_time()
        if principal.expires_at is None or principal.expires_at <= now_utc:
            raise SecurityAuthorizationError(f"Principal credential for '{clean_sub}' has expired.")
        if principal.issued_at is None or principal.issued_at > now_utc + timedelta(seconds=60):
            raise SecurityAuthorizationError(f"Principal credential for '{clean_sub}' was issued in the future.")

        with self._lock:
            if clean_key_id not in self._trusted_keys:
                raise SecurityAuthorizationError(
                    f"Credential signing key '{clean_key_id}' is no longer registered in service provider."
                )

        if cursor is not None:
            try:
                cursor.execute(
                    "SELECT 1 FROM revoked_signing_keys WHERE key_id = ?",
                    (clean_key_id,),
                )
                if cursor.fetchone() is not None:
                    raise KeyRevokedError(clean_key_id)
            except (SecurityAuthorizationError, KeyRevokedError):
                raise
            except Exception as e:
                raise SecurityAuthorizationError(
                    f"Database revocation query failure for key '{clean_key_id}': {e}"
                ) from e

            try:
                cursor.execute(
                    "SELECT 1 FROM revoked_attesting_principals WHERE principal_id = ?",
                    (clean_sub,),
                )
                if cursor.fetchone() is not None:
                    raise SecurityAuthorizationError(
                        f"Attesting principal '{clean_sub}' has been revoked in database."
                    )
            except (SecurityAuthorizationError, KeyRevokedError):
                raise
            except Exception as e:
                raise SecurityAuthorizationError(
                    f"Database revocation query failure for principal '{clean_sub}': {e}"
                ) from e
        else:
            if self.db_manager and hasattr(self.db_manager, "is_key_revoked"):
                if self.db_manager.is_key_revoked(clean_key_id):
                    raise KeyRevokedError(clean_key_id)
            if self.trust_store and hasattr(self.trust_store, "is_key_revoked"):
                if self.trust_store.is_key_revoked(clean_key_id):
                    raise KeyRevokedError(clean_key_id)

            if self.db_manager and hasattr(self.db_manager, "is_principal_revoked"):
                if self.db_manager.is_principal_revoked(clean_sub):
                    raise SecurityAuthorizationError(f"Migration principal '{clean_sub}' has been revoked.")
            if self.trust_store and hasattr(self.trust_store, "is_principal_revoked"):
                if self.trust_store.is_principal_revoked(clean_sub):
                    raise SecurityAuthorizationError(f"Migration principal '{clean_sub}' has been revoked.")

    @classmethod
    def mint_service_token(
        cls,
        principal_id: str,
        signing_key: Union[str, bytes, Any],
        key_id: str,
        issuer: str,
        audience: Any = "legacy_migration",
        scopes: Any = None,
        ttl_seconds: int = 3600,
        algorithm: str = "EdDSA",
        principal_type: Any = "service",
        jti: Any = None,
        include_jti: bool = True,
        iat: Any = None,
        exp: Any = None,
        nbf: Any = None,
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        clean_p = (principal_id or "").strip()
        now_ts = int(get_current_utc_time().timestamp())
        iat_val = now_ts if iat is None else iat
        exp_val = now_ts + ttl_seconds if exp is None else exp
        scopes_list = scopes if scopes is not None else ["legacy_migration"]

        header = {"alg": algorithm, "typ": "JWT", "kid": key_id}
        payload = {
            "iss": issuer,
            "aud": audience,
            "sub": clean_p,
            "principal_type": principal_type,
            "scope": scopes_list,
            "iat": iat_val,
            "exp": exp_val,
        }
        if include_jti and jti is not False:
            payload["jti"] = jti if jti is not None else str(uuid.uuid4())
        elif jti is not None and jti is not False:
            payload["jti"] = jti
        if nbf is not None:
            payload["nbf"] = nbf
        if extra_claims:
            payload.update(extra_claims)

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        if algorithm in ("HS256", "HMAC-SHA256"):
            coerced_key = cls._coerce_bytes(signing_key)
            sig_bytes = hmac.new(coerced_key, signing_input, hashlib.sha256).digest()
        elif algorithm in ("EdDSA", "Ed25519"):
            from cryptography.hazmat.primitives.asymmetric import ed25519
            if isinstance(signing_key, ed25519.Ed25519PrivateKey):
                priv = signing_key
            else:
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(cls._coerce_bytes(signing_key))
            sig_bytes = priv.sign(signing_input)
        else:
            raise ValueError(f"Unsupported algorithm '{algorithm}'")

        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("utf-8")
        return f"{header_b64}.{payload_b64}.{sig_b64}"


def create_test_authenticated_principal(
    principal_id: str,
    issuer: str = "test_archival_authority",
    audience: str = "legacy_migration",
    scopes: Optional[List[str]] = None,
    ttl_seconds: int = 3600,
    db_manager: Optional[Any] = None,
    provider: Optional[ServiceAuthenticationProvider] = None,
) -> AuthenticatedMigrationPrincipal:
    """Explicitly isolated testing fixture to obtain a genuine AuthenticatedMigrationPrincipal for tests.

    STRICT INVARIANT:
    - CANNOT be used in production (APP_ENV=production fails closed).
    - Mints a real ephemeral credential and verifies it through ServiceAuthenticationProvider.
    """
    app_env = resolve_app_env()
    if app_env in ("production", "prod", "staging", "qa"):
        raise SecurityAuthorizationError(
            f"create_test_authenticated_principal is strictly prohibited in '{app_env}' environment."
        )

    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    key_id = f"test_key_{principal_id}"

    if provider is None:
        provider = ServiceAuthenticationProvider(
            trusted_keys={key_id: {"key": pub, "algorithm": "Ed25519"}},
            trusted_issuers={issuer},
            expected_audience=audience,
            db_manager=db_manager,
        )
    else:
        provider.register_trusted_key(key_id, pub, algorithm="Ed25519")
        with provider._lock:
            provider._trusted_issuers.add(issuer)

    token = provider.mint_service_token(
        principal_id=principal_id,
        signing_key=priv,
        key_id=key_id,
        issuer=issuer,
        audience=audience,
        scopes=scopes or ["legacy_migration"],
        ttl_seconds=ttl_seconds,
        algorithm="EdDSA",
    )
    return provider.authenticate(token)


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

        # Determine algorithm policy with authoritative APP_ENV (Phase 9.1.2.9 Section 5.1)
        app_env = resolve_app_env()

        raw_env_policy = os.environ.get("LEGACY_EVIDENCE_POLICY")
        clean_env_policy = raw_env_policy.strip().lower() if raw_env_policy else None
        if clean_env_policy and clean_env_policy not in ("permissive", "production", "ed25519_only"):
            raise SecurityAuthorizationError(f"Unknown or invalid LEGACY_EVIDENCE_POLICY '{raw_env_policy}'")

        clean_arg_policy = algorithm_policy.strip().lower() if algorithm_policy else None
        if clean_arg_policy and clean_arg_policy not in ("permissive", "production", "ed25519_only"):
            raise SecurityAuthorizationError(f"Unknown legacy evidence algorithm policy '{algorithm_policy}'")

        if app_env == "production":
            # Production environment: require Ed25519-only verification; strictly reject permissive HMAC
            if clean_env_policy == "permissive":
                raise SecurityAuthorizationError(
                    "LEGACY_EVIDENCE_POLICY=permissive is strictly prohibited in production environment (APP_ENV=production)."
                )
            if clean_arg_policy == "permissive":
                raise SecurityAuthorizationError(
                    "Programmatic permissive algorithm policy override is strictly prohibited in production environment (APP_ENV=production)."
                )
            chosen_policy = clean_arg_policy or clean_env_policy or "production"
        elif app_env in ("staging", "qa"):
            # Staging / QA: fail closed against permissive HMAC unless explicitly testing
            if clean_env_policy == "permissive" or clean_arg_policy == "permissive":
                raise SecurityAuthorizationError(
                    f"Permissive HMAC policy is prohibited in '{app_env}' environment without approved testing configuration."
                )
            chosen_policy = clean_arg_policy or clean_env_policy or "production"
        elif app_env in ("development", "test"):
            # Development and testing: permit permissive policy for synthetic HMAC fixtures
            chosen_policy = clean_arg_policy or clean_env_policy or "permissive"
        else:
            raise SecurityAuthorizationError(
                f"Unrecognized or untrusted APP_ENV '{app_env}'. Legacy evidence trust store fails closed."
            )

        self.algorithm_policy = chosen_policy

        # Stage configuration for atomic validation
        staged_revoked_keys: Set[str] = set()
        staged_issuers: Set[str] = set()
        staged_principals: Set[str] = set(DEFAULT_AUTHORIZED_ATTESTING_PRINCIPALS)
        staged_revoked_principals: Set[str] = set()
        staged_keys: List[Tuple[str, Union[str, bytes], str]] = []

        # Load persisted revoked principals if DB manager is provided
        if self._db_manager and hasattr(self._db_manager, "get_revoked_principals"):
            try:
                db_revoked = self._db_manager.get_revoked_principals()
                if db_revoked:
                    staged_revoked_principals.update(db_revoked)
            except Exception as e:
                if app_env in ("production", "staging", "qa"):
                    raise SecurityAuthorizationError(
                        f"Failed to query durable revoked principals from database in '{app_env}': {e}"
                    ) from e
                logger.warning("Failed to load persisted revoked principals from DB: %s", e)

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
            if self._db_manager and hasattr(self._db_manager, "is_principal_revoked"):
                if self._db_manager.is_principal_revoked(clean_p):
                    self._revoked_principals.add(clean_p)
                    raise SecurityAuthorizationError(f"Cannot register attesting principal '{clean_p}': principal has been revoked in database.")
            if clean_p in ("candidate_user",) or clean_p.startswith("user_") or clean_p.startswith("candidate_"):
                raise SecurityAuthorizationError(f"Candidate user '{clean_p}' cannot be an attesting principal.")
            self._trusted_attesting_principals.add(clean_p)

    def revoke_attesting_principal(self, principal_id: str, reason: str = "Principal Revoked") -> None:
        """Revokes an attesting principal durably."""
        clean_p = (principal_id or "").strip()
        if not clean_p:
            raise SecurityAuthorizationError("Cannot revoke empty principal_id")
        with self._lock:
            self._revoked_principals.add(clean_p)
            self._trusted_attesting_principals.discard(clean_p)
            if self._db_manager and hasattr(self._db_manager, "record_principal_revocation"):
                try:
                    self._db_manager.record_principal_revocation(clean_p, reason=reason)
                except Exception as e:
                    logger.error("Failed to persist principal revocation in DB: %s", e)
                    raise SecurityAuthorizationError(f"Durable principal revocation failed for '{clean_p}': {e}") from e

    def is_attesting_principal_trusted(self, principal_id: str) -> bool:
        """Verifies whether an attesting principal is authorized and not revoked."""
        clean_p = (principal_id or "").strip()
        if not clean_p:
            return False
        with self._lock:
            if clean_p in self._revoked_principals:
                return False
            if self._db_manager:
                try:
                    if hasattr(self._db_manager, "is_principal_revoked"):
                        if self._db_manager.is_principal_revoked(clean_p):
                            self._revoked_principals.add(clean_p)
                            self._trusted_attesting_principals.discard(clean_p)
                            return False
                except Exception as e:
                    app_env = resolve_app_env()
                    if app_env in ("production", "staging", "qa") or self.algorithm_policy in ("production", "ed25519_only"):
                        raise SecurityAuthorizationError(
                            f"Database revocation query failure for principal '{clean_p}' in '{app_env}': {e}"
                        ) from e
                    logger.error("Database revocation query failed: %s", e)
                    return False
            elif self.algorithm_policy in ("production", "ed25519_only"):
                raise SecurityAuthorizationError("Missing database revocation authority in production.")

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

    def get_key_bytes(self, key_id: str) -> bytes:
        """Retrieves raw key bytes, raising error if revoked or unknown."""
        return self.get_key(key_id)[0]

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
    attesting_principal: Optional[Union[AuthenticatedMigrationPrincipal, str]] = None,
) -> Tuple[bytes, Dict[str, Any]]:
    """Helper for authorized migration authorities and tests to produce a canonical signed evidence artifact."""
    if evidence_type not in SUPPORTED_EVIDENCE_TYPES:
        raise ValidationError(f"Unsupported evidence_type '{evidence_type}'")
    if signature_algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ValidationError(f"Unsupported signature_algorithm '{signature_algorithm}'")
    if migration_boundary not in VALID_MIGRATION_BOUNDARIES:
        raise ValidationError(f"Invalid migration_boundary '{migration_boundary}'")

    issued = issued_at or get_current_utc_time().isoformat()

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
        if isinstance(attesting_principal, AuthenticatedMigrationPrincipal):
            payload_to_sign["attesting_principal"] = attesting_principal.principal_id.strip()
        else:
            payload_to_sign["attesting_principal"] = str(attesting_principal).strip()

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
        require_authenticated_context: Optional[bool] = None,
        service_authenticator: Optional[Any] = None,
    ):
        self.app_env = resolve_app_env()
        self.trust_store = trust_store or get_default_evidence_trust_store() or LegacyEvidenceTrustStore(db_manager=db_manager)
        self.resolver = resolver or get_default_evidence_resolver()
        self.db_manager = db_manager

        if self.db_manager is not None:
            db_auth = getattr(self.db_manager, "service_authenticator", None)
            if db_auth is not None and service_authenticator is not None:
                if db_auth is not service_authenticator:
                    raise SecurityAuthorizationError(
                        "Verifier service_authenticator conflicts with DatabaseManager's configured authenticator. "
                        "Verifier and database manager must share the exact same configured provider instance."
                    )
            elif db_auth is not None and service_authenticator is None:
                service_authenticator = db_auth
            elif db_auth is None and service_authenticator is not None:
                if hasattr(self.db_manager, "set_service_authenticator"):
                    self.db_manager.set_service_authenticator(service_authenticator)
                elif hasattr(self.db_manager, "service_authenticator"):
                    self.db_manager.service_authenticator = service_authenticator

        self._service_authenticator = service_authenticator

        is_production_like = (
            self.app_env in ("production", "staging", "qa")
            or self.trust_store.algorithm_policy in ("production", "ed25519_only")
        )

        if self.app_env in ("production", "staging", "qa"):
            if self.trust_store.algorithm_policy == "permissive":
                raise SecurityAuthorizationError(
                    f"Trust store algorithm policy 'permissive' is incompatible with '{self.app_env}' environment."
                )
            if self.service_authenticator is not None:
                auth_env = getattr(self.service_authenticator, "app_env", None)
                if auth_env not in ("production", "staging", "qa"):
                    raise SecurityAuthorizationError(
                        f"ServiceAuthenticationProvider configured for '{auth_env}' "
                        f"cannot be used in production-like environment '{self.app_env}'."
                    )

        if is_production_like:
            if require_authenticated_context is False:
                raise SecurityAuthorizationError(
                    "Disabling authenticated context enforcement (require_authenticated_context=False) "
                    f"is strictly prohibited in '{self.app_env}' environment."
                )
            self.require_authenticated_context = True
        elif require_authenticated_context is not None:
            self.require_authenticated_context = require_authenticated_context
        else:
            self.require_authenticated_context = False

    @property
    def service_authenticator(self) -> Optional[Any]:
        return self._service_authenticator

    @service_authenticator.setter
    def service_authenticator(self, provider: Optional[Any]) -> None:
        if self._service_authenticator is not None and provider is not self._service_authenticator:
            raise SecurityAuthorizationError(
                "LegacyEvidenceVerifier service authenticator is locked. Replacing configured authenticator with a different instance is strictly prohibited."
            )
        self._service_authenticator = provider
        if self.db_manager is not None and provider is not None:
            if hasattr(self.db_manager, "set_service_authenticator"):
                self.db_manager.set_service_authenticator(provider)
            elif hasattr(self.db_manager, "service_authenticator"):
                self.db_manager.service_authenticator = provider

    def set_resolver(self, resolver: Optional[LegacyEvidenceResolver]) -> None:
        self.resolver = resolver

    def _verify_artifact_for_audit(
        self,
        evidence_type: str,
        evidence_reference_id: str,
        user_id: int,
        job_description_id: int,
        source_snapshot_hash: str,
        attesting_principal: str,
    ) -> VerifiedLegacyEvidence:
        """Internal helper for auditing stored attestations against backing artifacts without live credentials."""
        clean_principal = attesting_principal.strip()
        if not self.trust_store.is_attesting_principal_trusted(clean_principal):
            raise SecurityAuthorizationError(
                f"Attesting principal '{clean_principal}' is not authorized or has been revoked."
            )

        if self.resolver is None:
            raise SecurityAuthorizationError("No evidence resolver configured; cannot verify attestation.")
        resolved = self.resolver.resolve_artifact(evidence_type, evidence_reference_id)
        if resolved is None:
            raise SecurityAuthorizationError(
                f"Referenced evidence artifact '{evidence_reference_id}' of type '{evidence_type}' could not be resolved or found."
            )
        raw_bytes, artifact_dict = resolved
        artifact_hash = hashlib.sha256(raw_bytes).hexdigest()

        if not isinstance(artifact_dict, dict):
            raise SecurityAuthorizationError("Evidence artifact is not a valid JSON dictionary.")

        if artifact_dict.get("evidence_type") != evidence_type:
            raise SecurityAuthorizationError("Evidence type mismatch in artifact.")
        if artifact_dict.get("evidence_reference_id") != evidence_reference_id:
            raise SecurityAuthorizationError("Evidence reference ID mismatch in artifact.")

        bound_principal = (
            artifact_dict.get("migration_attesting_principal")
            or artifact_dict.get("attesting_principal")
            or artifact_dict.get("authorized_principal")
        )
        if self.trust_store.algorithm_policy in ("production", "ed25519_only") and not bound_principal:
            raise SecurityAuthorizationError(
                f"Evidence artifact '{evidence_reference_id}' lacks mandatory attesting_principal binding required under production policy."
            )
        if bound_principal and str(bound_principal).strip() != clean_principal:
            raise SecurityAuthorizationError(
                f"Evidence artifact explicitly binds attesting principal '{bound_principal}', "
                f"which does not match attestation principal '{clean_principal}'."
            )

        issuer_id = str(artifact_dict.get("issuer_id", "")).strip()
        if not self.trust_store.is_issuer_trusted(issuer_id):
            raise SecurityAuthorizationError(f"Evidence issuer '{issuer_id}' is untrusted.")

        key_id = str(artifact_dict.get("key_id", "")).strip()
        if self.trust_store.is_key_revoked(key_id):
            raise KeyRevokedError(key_id)

        sig_algo = str(artifact_dict.get("signature_algorithm", "")).strip()
        if (self.app_env in ("production", "staging", "qa") or self.trust_store.algorithm_policy in ("production", "ed25519_only")) and sig_algo != "Ed25519":
            raise SecurityAuthorizationError("Signature algorithm rejected under Ed25519-only policy.")

        stored_sig = str(artifact_dict.get("signature") or artifact_dict.get("evidence_signature", "")).strip()
        payload_to_verify = {k: v for k, v in artifact_dict.items() if k not in ("signature", "evidence_signature")}
        payload_bytes = canonical_json_bytes(payload_to_verify)
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()

        if sig_algo == "Ed25519":
            from cryptography.hazmat.primitives.asymmetric import ed25519
            pub_key_bytes = self.trust_store.get_key_bytes(key_id)
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_key_bytes)
            raw_sig = bytes.fromhex(stored_sig) if all(c in "0123456789abcdefABCDEF" for c in stored_sig) else stored_sig.encode("utf-8")
            try:
                pub_key.verify(raw_sig, payload_bytes)
            except Exception:
                raise SecurityAuthorizationError("Cryptographic digital signature verification failed on evidence artifact.")
        elif sig_algo == "HMAC-SHA256":
            secret = self.trust_store.get_key_bytes(key_id)
            expected_sig = hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_sig.lower(), stored_sig.lower()):
                raise SecurityAuthorizationError("Cryptographic HMAC signature verification failed on evidence artifact.")

        entries = artifact_dict.get("entries", [])
        matched = False
        for entry in entries:
            if (
                entry.get("user_id") == user_id
                and entry.get("job_description_id") == job_description_id
                and entry.get("source_snapshot_hash") == source_snapshot_hash
            ):
                matched = True
                break
        if not matched:
            raise SecurityAuthorizationError("Evidence artifact payload does not bind the specified job description.")

        return VerifiedLegacyEvidence(
            _token=_VERIFICATION_TOKEN,
            evidence_type=evidence_type,
            evidence_reference_id=evidence_reference_id,
            evidence_artifact_hash=artifact_hash,
            evidence_payload_hash=payload_hash,
            user_id=user_id,
            job_description_id=job_description_id,
            source_snapshot_hash=source_snapshot_hash,
            migration_boundary=artifact_dict.get("migration_boundary", "pre_phase_9_1_1"),
            issuer_id=issuer_id,
            key_id=key_id,
            signature_algorithm=sig_algo,
            evidence_signature=stored_sig,
            verified_at=get_current_utc_time().isoformat(),
            attested_by=clean_principal,
            attesting_principal_id=clean_principal,
        )

    def verify(
        self,
        evidence_type: str,
        evidence_reference_id: str,
        user_id: int,
        job_description_id: int,
        source_snapshot_hash: str,
        attesting_principal: Optional[Union[AuthenticatedMigrationPrincipal, str]] = None,
        require_authenticated_context: Optional[bool] = None,
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
        app_env = resolve_app_env()
        is_production_like = (
            app_env in ("production", "staging", "qa")
            or self.trust_store.algorithm_policy in ("production", "ed25519_only")
        )

        if is_production_like and require_authenticated_context is False:
            raise SecurityAuthorizationError(
                "Method-level downgrade override (require_authenticated_context=False) "
                f"is strictly prohibited in '{app_env}' environment."
            )

        if is_production_like and self.db_manager is None:
            raise SecurityAuthorizationError(
                f"Authoritative DatabaseManager is mandatory for LegacyEvidenceVerifier in '{app_env}'."
            )

        effective_require_context = self.require_authenticated_context
        if require_authenticated_context is not None and not is_production_like:
            effective_require_context = require_authenticated_context

        # 1. Evidence type allowlist
        clean_type = (evidence_type or "").strip()
        if clean_type not in SUPPORTED_EVIDENCE_TYPES:
            raise SecurityAuthorizationError(
                f"Evidence type '{clean_type}' is not on the supported allowlist: {sorted(SUPPORTED_EVIDENCE_TYPES)}"
            )

        # 2. Attesting principal authorization & authenticated context verification (Phase 9.1.2.10)
        auth_principal_obj: Optional[AuthenticatedMigrationPrincipal] = None
        if attesting_principal is None:
            raise SecurityAuthorizationError("Missing authenticated service context: attesting_principal is required.")

        if isinstance(attesting_principal, AuthenticatedMigrationPrincipal):
            if attesting_principal._token is not _AUTH_TOKEN:
                raise SecurityAuthorizationError("Tampered or unverified AuthenticatedMigrationPrincipal context.")
            if is_production_like and self.service_authenticator is None:
                raise SecurityAuthorizationError(
                    "Production service authentication provider is not configured. Production legacy attestation creation is disabled."
                )
            if self.service_authenticator is not None:
                self.service_authenticator.validate_principal(attesting_principal)
            else:
                now_utc = get_current_utc_time()
                if attesting_principal.expires_at is not None and attesting_principal.expires_at <= now_utc:
                    raise SecurityAuthorizationError(f"Principal credential for '{attesting_principal.principal_id}' has expired.")
                if "legacy_migration" not in attesting_principal.scopes:
                    raise SecurityAuthorizationError(f"Principal '{attesting_principal.principal_id}' lacks legacy_migration authorization scope.")
            auth_principal_obj = attesting_principal
            clean_principal = attesting_principal.principal_id.strip()
        elif isinstance(attesting_principal, str):
            clean_str = attesting_principal.strip()
            if not clean_str:
                raise SecurityAuthorizationError("Attesting principal is required and cannot be empty.")

            if self.service_authenticator and "." in clean_str:
                auth_p = self.service_authenticator.authenticate(clean_str)
                auth_principal_obj = auth_p
                clean_principal = auth_p.principal_id.strip()
            elif is_production_like or effective_require_context:
                raise SecurityAuthorizationError(
                    "Caller cannot authenticate by supplying an arbitrary allowed string. "
                    "An AuthenticatedMigrationPrincipal context is required."
                )
            else:
                clean_principal = clean_str
        else:
            raise SecurityAuthorizationError(
                f"Invalid attesting_principal type '{type(attesting_principal).__name__}'. "
                "An AuthenticatedMigrationPrincipal context is required."
            )

        # In production, require service authentication provider (Finding 2)
        if is_production_like and self.service_authenticator is None:
            raise SecurityAuthorizationError(
                "Production service authentication provider is not configured. Production legacy attestation creation is disabled."
            )

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

        if (is_production_like or self.trust_store.algorithm_policy in ("production", "ed25519_only")) and algorithm != "Ed25519":
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

        # Check explicit bound principal in artifact
        bound_principal = artifact_dict.get("attesting_principal") or artifact_dict.get("authorized_principal")
        if self.trust_store.algorithm_policy in ("production", "ed25519_only") and not bound_principal:
            raise SecurityAuthorizationError(
                f"Evidence artifact '{clean_ref}' lacks mandatory attesting_principal binding required under production policy."
            )
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

        verified_at = get_current_utc_time().isoformat()

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
            attesting_principal_id=auth_principal_obj.principal_id if auth_principal_obj else clean_principal,
            provider_instance_id=auth_principal_obj._provider_instance_id if auth_principal_obj else "",
            credential_id=auth_principal_obj.credential_id or "" if auth_principal_obj else "",
            credential_key_id=auth_principal_obj.credential_key_id or "" if auth_principal_obj else "",
            issuer=auth_principal_obj.issuer if auth_principal_obj else "",
            audience=auth_principal_obj.audience if auth_principal_obj else "",
            scopes=tuple(auth_principal_obj.scopes) if auth_principal_obj else (),
            issued_at=auth_principal_obj.issued_at.isoformat() if auth_principal_obj and auth_principal_obj.issued_at else "",
            expires_at=auth_principal_obj.expires_at.isoformat() if auth_principal_obj and auth_principal_obj.expires_at else "",
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

        # Check that attesting principal is authorized and NOT revoked
        if not self.trust_store.is_attesting_principal_trusted(clean_att_by):
            raise SecurityAuthorizationError(
                f"Attesting principal '{clean_att_by}' in stored attestation is revoked or not authorized in trust store."
            )

        # Independently resolve and verify the backing artifact for audit
        verified = self._verify_artifact_for_audit(
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

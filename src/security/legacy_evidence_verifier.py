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
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Set, Tuple, Union
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


@dataclass(frozen=True)
class AuthenticatedMigrationPrincipal:
    """Represents a verified service identity authorized to verify and attest historical legacy evidence.

    Security Invariant (Phase 9.1.2.9):
    - Cannot be directly constructed by callers or manufactured with unverified Boolean flags.
    - Can ONLY be issued by ServiceAuthenticationProvider after authenticating genuine credentials.
    - Bound to 'legacy_migration' authorization scope.
    - Candidate users are strictly prohibited from holding this context.
    """

    _token: Any = None
    principal_id: str = ""
    issuer: str = "internal_service_authority"
    audience: str = "legacy_migration"
    scopes: Tuple[str, ...] = ("legacy_migration",)
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    credential_id: Optional[str] = None
    principal_type: str = "service"
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
        if self.principal_type in ("candidate", "unauthenticated", "anonymous"):
            raise SecurityAuthorizationError(f"Invalid principal_type '{self.principal_type}' for migration principal.")
        if "legacy_migration" not in self.scopes and "all" not in self.scopes:
            raise SecurityAuthorizationError(f"Principal '{clean_id}' lacks legacy_migration authorization scope.")
        if self.expires_at is not None:
            now_utc = datetime.now(timezone.utc)
            if self.expires_at <= now_utc:
                raise SecurityAuthorizationError(f"Principal credential for '{clean_id}' has expired.")

    @property
    def is_authenticated(self) -> bool:
        """Always True because instances can only be minted by ServiceAuthenticationProvider."""
        return True

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

    def __post_init__(self) -> None:
        if self._token is not _VERIFICATION_TOKEN:
            raise SecurityAuthorizationError(
                "VerifiedLegacyEvidence cannot be instantiated directly. "
                "Must be produced by LegacyEvidenceVerifier.verify()."
            )


class ServiceAuthenticationProvider:
    """Authenticates internal service credentials and issues AuthenticatedMigrationPrincipal instances.

    Security Boundary (Phase 9.1.2.9):
    - Validates cryptographic signatures (Ed25519 or HMAC-SHA256 based on policy).
    - In production, strictly enforces Ed25519 signatures and rejects HMAC.
    - Validates trusted issuer, intended audience, principal identity, scopes, and expiration.
    - Enforces revocation checks against DatabaseManager and trust store.
    - Rejects candidate identities, expired credentials, invalid signatures, wrong scopes.
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
        self._trusted_keys: Dict[str, Tuple[bytes, str]] = {}
        self._trusted_issuers: Set[str] = set()

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
            for k_id, k_val in trusted_keys.items():
                self.register_trusted_key(k_id, k_val)

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

        try:
            payload_json = self._b64url_decode(payload_b64).decode("utf-8")
            payload = json.loads(payload_json)
        except Exception as e:
            raise SecurityAuthorizationError(f"Invalid service credential payload: {e}")

        try:
            signature_bytes = self._b64url_decode(sig_b64)
        except Exception as e:
            raise SecurityAuthorizationError(f"Invalid service credential signature encoding: {e}")

        alg = header.get("alg")
        if not alg or alg == "none":
            raise SecurityAuthorizationError("Unsigned service credentials (alg='none') are strictly prohibited.")

        if self.app_env in ("production", "staging", "qa") and alg in ("HS256", "HMAC-SHA256"):
            raise SecurityAuthorizationError(
                f"HMAC service credentials are prohibited under '{self.app_env}' policy. Production requires EdDSA / Ed25519."
            )

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
                raise SecurityAuthorizationError(f"Service signing key '{clean_kid}' has been revoked.")

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
        if not iss or not str(iss).strip():
            raise SecurityAuthorizationError("Service credential payload missing mandatory 'iss' claim.")
        clean_iss = str(iss).strip()
        with self._lock:
            if clean_iss not in self._trusted_issuers:
                raise SecurityAuthorizationError(f"Untrusted service credential issuer '{clean_iss}'.")

        aud = payload.get("aud")
        if not aud:
            raise SecurityAuthorizationError("Service credential payload missing mandatory 'aud' claim.")
        aud_list = [aud] if isinstance(aud, str) else list(aud)
        if self.expected_audience not in aud_list:
            raise SecurityAuthorizationError(
                f"Service credential audience '{aud}' does not match expected audience '{self.expected_audience}'."
            )

        sub = payload.get("sub") or payload.get("principal_id")
        if not sub or not str(sub).strip():
            raise SecurityAuthorizationError("Service credential payload missing mandatory 'sub' claim.")
        clean_sub = str(sub).strip()

        if clean_sub in ("candidate_user",) or clean_sub.startswith("user_") or clean_sub.startswith("candidate_"):
            raise SecurityAuthorizationError(f"Candidate user '{clean_sub}' cannot be an authenticated service principal.")

        ptype = payload.get("principal_type", "service")
        if ptype in ("candidate", "unauthenticated", "anonymous"):
            raise SecurityAuthorizationError(f"Invalid principal_type '{ptype}' in service credential.")

        raw_scopes = payload.get("scope") or payload.get("scopes") or []
        if isinstance(raw_scopes, str):
            scopes = tuple(raw_scopes.split())
        else:
            scopes = tuple(raw_scopes)
        if "legacy_migration" not in scopes and "all" not in scopes:
            raise SecurityAuthorizationError("Service credential lacks mandatory 'legacy_migration' authorization scope.")

        exp = payload.get("exp")
        if exp is None:
            raise SecurityAuthorizationError("Service credential payload missing mandatory 'exp' claim.")
        try:
            exp_float = float(exp)
        except (ValueError, TypeError):
            raise SecurityAuthorizationError("Invalid 'exp' timestamp in service credential.")

        now_utc = datetime.now(timezone.utc)
        if exp_float <= now_utc.timestamp():
            raise SecurityAuthorizationError(f"Service credential has expired (exp={exp_float}).")

        iat = payload.get("iat")
        if iat is not None:
            try:
                iat_float = float(iat)
                if iat_float > now_utc.timestamp() + 300:
                    raise SecurityAuthorizationError("Service credential issued in the future.")
                issued_at_dt = datetime.fromtimestamp(iat_float, tz=timezone.utc)
            except (ValueError, TypeError):
                issued_at_dt = now_utc
        else:
            issued_at_dt = now_utc

        expires_at_dt = datetime.fromtimestamp(exp_float, tz=timezone.utc)

        if self.db_manager and hasattr(self.db_manager, "is_principal_revoked"):
            if self.db_manager.is_principal_revoked(clean_sub):
                raise SecurityAuthorizationError(f"Migration principal '{clean_sub}' has been revoked.")

        if self.trust_store and hasattr(self.trust_store, "is_principal_revoked"):
            if self.trust_store.is_principal_revoked(clean_sub):
                raise SecurityAuthorizationError(f"Migration principal '{clean_sub}' has been revoked.")

        jti = payload.get("jti")

        return AuthenticatedMigrationPrincipal(
            _token=_AUTH_TOKEN,
            principal_id=clean_sub,
            issuer=clean_iss,
            audience=self.expected_audience,
            scopes=scopes,
            issued_at=issued_at_dt,
            expires_at=expires_at_dt,
            credential_id=str(jti) if jti else None,
            principal_type=ptype,
        )

    @classmethod
    def mint_service_token(
        cls,
        principal_id: str,
        signing_key: Union[str, bytes, Any],
        key_id: str,
        issuer: str,
        audience: str = "legacy_migration",
        scopes: Optional[List[str]] = None,
        ttl_seconds: int = 3600,
        algorithm: str = "EdDSA",
        principal_type: str = "service",
        jti: Optional[str] = None,
    ) -> str:
        clean_p = (principal_id or "").strip()
        now_ts = int(datetime.now(timezone.utc).timestamp())
        exp_ts = now_ts + ttl_seconds
        scopes_list = scopes or ["legacy_migration"]
        token_id = jti or str(uuid.uuid4())

        header = {"alg": algorithm, "typ": "JWT", "kid": key_id}
        payload = {
            "iss": issuer,
            "aud": audience,
            "sub": clean_p,
            "principal_type": principal_type,
            "scope": scopes_list,
            "iat": now_ts,
            "exp": exp_ts,
            "jti": token_id,
        }

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

    provider = ServiceAuthenticationProvider(
        trusted_keys={key_id: {"key": pub, "algorithm": "Ed25519"}},
        trusted_issuers={issuer},
        expected_audience=audience,
        db_manager=db_manager,
    )
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
        self.service_authenticator = service_authenticator

        is_production_like = (
            self.app_env in ("production", "staging", "qa")
            or self.trust_store.algorithm_policy in ("production", "ed25519_only")
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
        if self.trust_store.algorithm_policy in ("production", "ed25519_only") and sig_algo != "Ed25519":
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
            verified_at=datetime.now(timezone.utc).isoformat(),
            attested_by=clean_principal,
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

        # 2. Attesting principal authorization & authenticated context verification (Phase 9.1.2.9)
        if attesting_principal is None:
            raise SecurityAuthorizationError("Missing authenticated service context: attesting_principal is required.")

        if isinstance(attesting_principal, AuthenticatedMigrationPrincipal):
            if attesting_principal._token is not _AUTH_TOKEN:
                raise SecurityAuthorizationError("Tampered or unverified AuthenticatedMigrationPrincipal context.")
            clean_principal = attesting_principal.principal_id.strip()
        elif isinstance(attesting_principal, str):
            clean_str = attesting_principal.strip()
            if not clean_str:
                raise SecurityAuthorizationError("Attesting principal is required and cannot be empty.")

            if self.service_authenticator and "." in clean_str:
                auth_p = self.service_authenticator.authenticate(clean_str)
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

        # In production, require service authenticator or genuine AuthenticatedMigrationPrincipal
        if is_production_like and self.service_authenticator is None and not isinstance(attesting_principal, AuthenticatedMigrationPrincipal):
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

"""Server-side candidate authentication, session-bound authorization, and HMAC key rotation management."""

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Optional, Set, Tuple, Union

from src.database.exceptions import (
    InvalidSessionError,
    InvalidTicketError,
    KeyRevokedError,
    SecurityAuthorizationError,
    SessionExpiredError,
    TicketAlreadyConsumedError,
)
from src.utils.logger import setup_logger

logger = setup_logger("SessionManager")

DEFAULT_DEV_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class KeyRotationManager:
    """Manages HMAC signing keys with support for Graceful (Mode A) and Emergency (Mode B) rotation."""

    MODE_GRACEFUL = "MODE_A_GRACEFUL"
    MODE_EMERGENCY = "MODE_B_EMERGENCY"

    def __init__(
        self,
        initial_key_id: str = "v1",
        initial_secret: Optional[Union[str, bytes]] = None,
    ):
        self.active_key_id = initial_key_id
        self._keys: Dict[str, bytes] = {}
        self._retired_keys: Dict[str, Tuple[bytes, float]] = {}  # key_id -> (secret, expires_at)
        self._revoked_keys: Set[str] = set()

        if initial_secret:
            secret_bytes = self._coerce_bytes(initial_secret)
        else:
            env_secret = os.environ.get("ACTION_TICKET_SECRET_KEY")
            if env_secret:
                secret_bytes = self._coerce_bytes(env_secret)
            else:
                secret_bytes = secrets.token_bytes(32)

        if len(secret_bytes) < 32:
            raise SecurityAuthorizationError("Signing secret must have at least 32 bytes (256 bits) of entropy.")

        self._keys[initial_key_id] = secret_bytes

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

    def get_signing_key(self) -> Tuple[str, bytes]:
        """Returns the active (key_id, secret_bytes) for signing new action tickets."""
        return self.active_key_id, self._keys[self.active_key_id]

    def get_verification_key(self, key_id: str) -> bytes:
        """Retrieves key for verifying a ticket. Raises KeyRevokedError if revoked or unknown."""
        if key_id in self._revoked_keys:
            raise KeyRevokedError(key_id)

        if key_id in self._keys:
            return self._keys[key_id]

        if key_id in self._retired_keys:
            secret, expires_at = self._retired_keys[key_id]
            if time.time() < expires_at:
                return secret
            raise KeyRevokedError(key_id)

        raise KeyRevokedError(key_id)

    def rotate_keys(
        self,
        new_key_id: str,
        new_secret: Union[str, bytes],
        mode: str = MODE_GRACEFUL,
        overlap_window_seconds: int = 900,
    ) -> None:
        """Rotates active signing key.
        - Mode A (Graceful): Previous key moved to retired status with overlap window.
        - Mode B (Emergency): Previous key immediately revoked.
        """
        new_bytes = self._coerce_bytes(new_secret)
        if len(new_bytes) < 32:
            raise SecurityAuthorizationError("New signing secret must have at least 32 bytes.")

        old_key_id = self.active_key_id
        old_secret = self._keys.get(old_key_id)

        if mode == self.MODE_GRACEFUL:
            if old_secret:
                self._retired_keys[old_key_id] = (old_secret, time.time() + overlap_window_seconds)
            logger.info("Graceful key rotation: active %s -> %s (retired %s for %ds)", old_key_id, new_key_id, old_key_id, overlap_window_seconds)
        elif mode == self.MODE_EMERGENCY:
            self._revoked_keys.add(old_key_id)
            if old_key_id in self._retired_keys:
                del self._retired_keys[old_key_id]
            logger.warning("EMERGENCY key rotation: revoked %s immediately, active is now %s", old_key_id, new_key_id)
        else:
            raise ValueError(f"Unknown rotation mode: {mode}")

        self._keys[new_key_id] = new_bytes
        self.active_key_id = new_key_id


@dataclass
class CandidateSession:
    """Represents an active server-side candidate authenticated session."""
    session_id: str
    candidate_id: str
    candidate_name: str
    created_at: float
    expires_at: Union[float, datetime]
    last_activity: Union[float, datetime] = field(default_factory=time.time)
    user_id: Optional[int] = None
    email: Optional[str] = None
    csrf_token: str = field(default_factory=lambda: secrets.token_hex(32))
    is_active: bool = True
    issued_tickets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    consumed_tickets: Set[str] = field(default_factory=set)

    @property
    def is_expired(self) -> bool:
        now = time.time()
        exp = self.expires_at.timestamp() if isinstance(self.expires_at, datetime) else float(self.expires_at)
        act = self.last_activity.timestamp() if isinstance(self.last_activity, datetime) else float(self.last_activity)
        if now > exp:
            return True
        if now - act > 3600:
            return True
        return False

    def touch(self) -> None:
        """Updates last activity timestamp for sliding expiration."""
        self.last_activity = time.time()


class SessionManager:
    """Manages candidate authentication, server-side sessions, and cryptographic action tickets."""

    _instance: Optional["SessionManager"] = None

    def __init__(
        self,
        server_secret: Optional[bytes] = None,
        active_key_id: Optional[str] = None,
        rotation_keys: Optional[Dict[str, bytes]] = None,
    ):
        self._sessions: Dict[str, CandidateSession] = {}
        self._active_key_id = active_key_id or os.environ.get("ACTION_TICKET_ACTIVE_KEY_ID", "v1")
        self._rotation_keys: Dict[str, bytes] = {}

        # 1. Initialize keys from environment or parameter
        if server_secret:
            self._rotation_keys[self._active_key_id] = server_secret
        else:
            env_secret = os.environ.get("ACTION_TICKET_SECRET_KEY")
            app_env = os.environ.get("APP_ENV", "development").lower()

            if env_secret:
                try:
                    # Support hex or raw bytes
                    secret_bytes = bytes.fromhex(env_secret) if len(env_secret) >= 64 and all(c in "0123456789abcdefABCDEF" for c in env_secret) else env_secret.encode("utf-8")
                except ValueError:
                    secret_bytes = env_secret.encode("utf-8")

                if len(secret_bytes) < 32:
                    raise SecurityAuthorizationError(
                        f"ACTION_TICKET_SECRET_KEY has insufficient entropy ({len(secret_bytes)} bytes < 32 bytes required)."
                    )
                self._rotation_keys[self._active_key_id] = secret_bytes
            elif app_env in ("development", "test"):
                logger.info("Using ephemeral 256-bit test secret for SessionManager.")
                self._rotation_keys[self._active_key_id] = secrets.token_bytes(32)
            else:
                raise SecurityAuthorizationError("ACTION_TICKET_SECRET_KEY must be configured in production environment.")

        # 2. Load additional rotation keys if provided in environment
        if rotation_keys:
            self._rotation_keys.update(rotation_keys)
        else:
            rot_env = os.environ.get("ACTION_TICKET_ROTATION_KEYS")
            if rot_env:
                try:
                    raw_dict = json.loads(rot_env)
                    for k_id, k_val in raw_dict.items():
                        if isinstance(k_val, str):
                            k_bytes = bytes.fromhex(k_val) if len(k_val) >= 64 and all(c in "0123456789abcdefABCDEF" for c in k_val) else k_val.encode("utf-8")
                            self._rotation_keys[k_id] = k_bytes
                except Exception as e:
                    logger.warning("Could not parse ACTION_TICKET_ROTATION_KEYS JSON: %s", e)

        # Primary secret property
        self._server_secret = self._rotation_keys.get(self._active_key_id, list(self._rotation_keys.values())[0])

        # Initialize KeyRotationManager with loaded keys
        self.key_rotation_mgr = KeyRotationManager(
            initial_key_id=self._active_key_id,
            initial_secret=self._server_secret,
        )
        for k_id, k_val in self._rotation_keys.items():
            if k_id != self._active_key_id:
                self.key_rotation_mgr._keys[k_id] = k_val

        if SessionManager._instance is None:
            SessionManager._instance = self

    @property
    def active_key_id(self) -> str:
        return self.key_rotation_mgr.active_key_id

    def create_user_session(
        self,
        user_id: int,
        email: str,
        candidate_name: str = "Candidate User",
        ttl_seconds: int = 3600,
    ) -> CandidateSession:
        """Creates an authenticated candidate session bound to user_id and email."""
        return self.authenticate_candidate(
            candidate_id=str(user_id),
            candidate_name=candidate_name,
            ttl_seconds=ttl_seconds,
            user_id=user_id,
            email=email,
        )

    def get_session(self, session_id: str) -> CandidateSession:
        """Retrieves and validates an active candidate session."""
        return self.validate_session(session_id)

    def validate_csrf(self, session_id: str, csrf_token: Optional[str]) -> bool:
        """Validates CSRF token for a given session."""
        try:
            return self.validate_csrf_token(session_id, csrf_token)
        except InvalidSessionError:
            return False

    def create_action_ticket(
        self,
        action_type: str,
        resource_id: Union[str, int],
        packet_version_hash: str = "default_hash",
        candidate_id: str = "candidate_1",
        session_id: Optional[str] = None,
        ttl_seconds: int = 900,
    ) -> str:
        """Creates a signed action ticket containing ticket metadata and HMAC signature."""
        key_id, signing_key = self.key_rotation_mgr.get_signing_key()
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())

        # Canonical message string
        message = f"{action_type}:{resource_id}:{packet_version_hash}:{nonce}:{timestamp}"
        sig = hmac.new(signing_key, message.encode("utf-8"), hashlib.sha256).hexdigest()

        return f"TKT-{key_id}-{nonce}.{action_type}.{resource_id}.{packet_version_hash}.{timestamp}.{sig}"

    def verify_action_ticket(
        self,
        ticket_str: str,
        expected_action: Optional[str] = None,
        expected_resource_id: Optional[Union[str, int]] = None,
        expected_packet_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validates action ticket signature and structure, verifying against KeyRotationManager."""
        if not ticket_str or not isinstance(ticket_str, str):
            raise InvalidTicketError("Missing action ticket.")

        if not ticket_str.startswith("TKT-") or "." not in ticket_str:
            raise InvalidTicketError("Malformed action ticket format.")

        body = ticket_str[4:]
        parts = body.split(".")
        if len(parts) != 6:
            raise InvalidTicketError(f"Malformed ticket segments (expected 6, got {len(parts)}).")

        header_nonce, action_type, resource_id, packet_version_hash, ts_str, signature = parts
        try:
            timestamp = int(ts_str)
        except ValueError:
            raise InvalidTicketError("Corrupt timestamp in action ticket.")

        if "-" in header_nonce:
            key_id, nonce = header_nonce.split("-", 1)
        else:
            key_id = self.key_rotation_mgr.active_key_id
            nonce = header_nonce

        # Fetch verification key (raises KeyRevokedError if revoked)
        key_secret = self.key_rotation_mgr.get_verification_key(key_id)

        # Check expiration (default 3600s max lifetime if not provided)
        now = time.time()
        if now - timestamp > 3600:
            raise SecurityAuthorizationError("Action ticket has expired.")

        # Verify HMAC signature
        message = f"{action_type}:{resource_id}:{packet_version_hash}:{nonce}:{timestamp}"
        expected_sig = hmac.new(key_secret, message.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            raise InvalidTicketError("Action ticket signature verification failed (tampered ticket or wrong key).")

        if expected_action and expected_action != action_type:
            raise InvalidTicketError(f"Action ticket action mismatch: expected {expected_action}, got {action_type}.")

        if expected_resource_id and str(expected_resource_id) != str(resource_id):
            raise InvalidTicketError(f"Action ticket resource ID mismatch: expected {expected_resource_id}, got {resource_id}.")

        if expected_packet_hash and expected_packet_hash != packet_version_hash:
            raise InvalidTicketError(f"Action ticket packet hash mismatch: expected {expected_packet_hash}, got {packet_version_hash}.")

        return {
            "nonce": nonce,
            "key_id": key_id,
            "action_type": action_type,
            "resource_id": resource_id,
            "packet_version_hash": packet_version_hash,
            "timestamp": timestamp,
        }

    @classmethod
    def get_instance(cls) -> "SessionManager":
        """Singleton accessor for server-side session management."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Resets the singleton instance (useful for clean testing environments)."""
        cls._instance = None

    def configure_keys(self, active_key_id: str, keys: Dict[str, bytes]) -> None:
        """Configures HMAC keys for graceful or emergency secret rotation."""
        if active_key_id not in keys:
            raise ValueError(f"Active key '{active_key_id}' must be present in the keys dictionary.")
        for k_id, k_val in keys.items():
            if len(k_val) < 32:
                raise ValueError(f"Key '{k_id}' has insufficient entropy ({len(k_val)} bytes < 32 bytes).")
        self._active_key_id = active_key_id
        self._rotation_keys = dict(keys)
        self._server_secret = self._rotation_keys[active_key_id]
        self.key_rotation_mgr.active_key_id = active_key_id
        self.key_rotation_mgr._keys = dict(keys)
        logger.info("SessionManager keys rotated: active key is '%s' (%d total keys)", active_key_id, len(keys))

    def authenticate_candidate(
        self,
        candidate_id: str,
        candidate_name: str,
        pin_or_secret: Optional[str] = None,
        ttl_seconds: int = 3600,
        user_id: Optional[int] = None,
        email: Optional[str] = None,
    ) -> CandidateSession:
        """Establishes an authenticated server-side session bound to candidate and user_id."""
        if not candidate_id or not candidate_id.strip():
            raise InvalidSessionError("Candidate ID cannot be empty.")
        if not candidate_name or not candidate_name.strip():
            raise InvalidSessionError("Candidate name cannot be empty.")

        clean_id = candidate_id.strip()
        clean_name = candidate_name.strip()

        # Reject automated bot identifiers
        prohibited = ["bot", "agent", "system", "auto", "daemon", "scraper", "matcher"]
        if any(p in clean_id.lower() or p in clean_name.lower() for p in prohibited):
            raise InvalidSessionError(
                f"Authentication rejected: '{clean_name}' indicates automated process. Human candidate required."
            )

        # Derive user_id if clean_id is numeric
        derived_user_id = user_id
        if derived_user_id is None and clean_id.isdigit():
            derived_user_id = int(clean_id)

        session_id = secrets.token_hex(32)
        now = time.time()
        session = CandidateSession(
            session_id=session_id,
            candidate_id=clean_id,
            candidate_name=clean_name,
            created_at=now,
            expires_at=now + ttl_seconds,
            last_activity=now,
            user_id=derived_user_id,
            email=email,
            csrf_token=secrets.token_hex(32),
            is_active=True,
        )
        self._sessions[session_id] = session
        logger.info("Authenticated candidate session created: %s... for %s (User #%s)", session_id[:8], clean_name, str(derived_user_id))
        return session

    def regenerate_session_id(self, old_session_id: str) -> CandidateSession:
        """Session fixation protection: issues a new session ID and revokes the old ID."""
        session = self.validate_session(old_session_id)
        new_session_id = secrets.token_hex(32)

        del self._sessions[old_session_id]
        session.session_id = new_session_id
        session.touch()
        self._sessions[new_session_id] = session
        logger.info("Regenerated session ID for User #%s (%s... -> %s...)", str(session.user_id), old_session_id[:8], new_session_id[:8])
        return session

    def validate_session(self, session_id: Optional[str]) -> CandidateSession:
        """Validates that a session exists, is active, and is unexpired."""
        if not session_id or session_id not in self._sessions:
            raise InvalidSessionError("Missing or invalid candidate session.")

        session = self._sessions[session_id]

        if session.is_expired:
            session.is_active = False
            logger.warning("Candidate session %s... expired.", session_id[:8])
            raise SessionExpiredError(f"Candidate session {session_id[:8]}... has expired. Re-authentication required.")

        if not session.is_active:
            raise InvalidSessionError("Candidate session has been revoked or deactivated.")

        session.touch()
        return session

    def validate_csrf_token(self, session_id: str, csrf_token: Optional[str]) -> bool:
        """Validates CSRF token for state-changing operations."""
        session = self.validate_session(session_id)
        if not csrf_token or not isinstance(csrf_token, str):
            return False
        return hmac.compare_digest(session.csrf_token, csrf_token.strip())

    def issue_action_ticket(
        self,
        session_id: str,
        action_type: str,
        application_id: int,
        packet_hash: str,
        ttl_seconds: int = 900,
    ) -> str:
        """Issues a single-use cryptographically signed action ticket bound to active key_id."""
        session = self.validate_session(session_id)

        if not action_type or not packet_hash:
            raise ValueError("action_type and packet_hash are mandatory for ticket issuance.")

        nonce = secrets.token_hex(16)
        timestamp = int(time.time())
        key_id, signing_key = self.key_rotation_mgr.get_signing_key()

        message = f"{session.session_id}:{key_id}:{action_type}:{application_id}:{packet_hash}:{nonce}:{timestamp}"
        signature = hmac.new(signing_key, message.encode("utf-8"), hashlib.sha256).hexdigest()

        ticket_str = f"TKT-{key_id}-{nonce}.{timestamp}.{signature}"
        session.issued_tickets[nonce] = {
            "key_id": key_id,
            "action_type": action_type,
            "application_id": application_id,
            "packet_hash": packet_hash,
            "timestamp": timestamp,
            "ttl": ttl_seconds,
        }
        logger.info("Issued single-use action ticket for %s (Key %s, App #%d, Nonce %s...)", action_type, key_id, application_id, nonce[:8])
        return ticket_str

    @classmethod
    def parse_action_ticket(cls, ticket_str: str) -> Tuple[str, str, int, str]:
        """Parses an action ticket into constituent (key_id, nonce, timestamp, signature).

        Expected format: TKT-{key_id}-{nonce}.{timestamp}.{signature}
        (or legacy format: TKT-{nonce}.{timestamp}.{signature})

        Returns:
            Tuple of (key_id, nonce, timestamp, signature)
        Raises:
            ValueError: If the ticket is missing, malformed, or has an invalid structure or timestamp.
        """
        if not ticket_str or not isinstance(ticket_str, str) or not ticket_str.strip():
            raise ValueError("Missing action ticket.")

        clean_ticket = ticket_str.strip()
        if not clean_ticket.startswith("TKT-") or "." not in clean_ticket:
            raise ValueError("Malformed action ticket.")

        body = clean_ticket[4:]
        parts = body.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid action ticket structure.")

        header_nonce, ts_str, signature = parts
        try:
            timestamp = int(ts_str)
        except ValueError:
            raise ValueError("Corrupt timestamp in action ticket.")

        if not signature:
            raise ValueError("Missing signature in action ticket.")

        if "-" in header_nonce:
            key_id, nonce = header_nonce.rsplit("-", 1)
        else:
            key_id = "v1"
            nonce = header_nonce

        if not key_id.strip() or not nonce.strip():
            raise ValueError("Action ticket missing key_id or nonce.")

        return key_id, nonce, timestamp, signature

    def verify_and_consume_action_ticket(
        self,
        session_id: str,
        ticket_str: Optional[str],
        action_type: str,
        application_id: int,
        packet_hash: str,
        db_manager: Optional[Any] = None,
    ) -> Tuple[bool, str]:
        """Cryptographically verifies and consumes an action ticket with rotation & replay checks."""
        try:
            session = self.validate_session(session_id)
        except (InvalidSessionError, SessionExpiredError) as e:
            return False, f"Authorization rejected: {e}"

        if not ticket_str or not isinstance(ticket_str, str):
            return False, "Authorization rejected: Missing action ticket."

        # Explicitly reject hardcoded dummy constants
        if ticket_str in ("CANDIDATE_VERIFIED_DASHBOARD_APPROVAL", "CANDIDATE_VERIFIED_MANUAL_SUBMISSION"):
            return False, "Authorization rejected: Static constant token rejected. Authenticated session ticket required."

        try:
            key_id, nonce, timestamp, signature = self.parse_action_ticket(ticket_str)
        except ValueError as err:
            return False, f"Authorization rejected: {err}"

        # Rotation & Revocation check via KeyRotationManager
        try:
            key_secret = self.key_rotation_mgr.get_verification_key(key_id)
        except KeyRevokedError as err:
            logger.error("Ticket verification rejected: key '%s' has been revoked or expired: %s", key_id, err)
            return False, f"Authorization rejected: Action ticket signed with revoked or retired key '{key_id}'. Key rotation in effect. Fresh candidate authorization required."

        # Check for in-memory replay
        if nonce in session.consumed_tickets:
            logger.warning("Replay attack detected: Ticket nonce %s... already consumed.", nonce[:8])
            return False, "Authorization rejected: Replay attack detected. Action ticket has already been used."

        if nonce not in session.issued_tickets:
            return False, "Authorization rejected: Unrecognized or unissued action ticket."

        meta = session.issued_tickets[nonce]

        # Check expiry
        now = time.time()
        if now - timestamp > meta["ttl"]:
            return False, "Authorization rejected: Action ticket has expired."

        # Verify HMAC cryptographic signature
        expected_msg = f"{session.session_id}:{key_id}:{action_type}:{application_id}:{packet_hash}:{nonce}:{timestamp}"
        expected_sig = hmac.new(key_secret, expected_msg.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            # Check legacy message format without key_id
            legacy_msg = f"{session.session_id}:{action_type}:{application_id}:{packet_hash}:{nonce}:{timestamp}"
            legacy_sig = hmac.new(key_secret, legacy_msg.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, legacy_sig):
                logger.error("Action ticket signature forgery attempt detected.")
                return False, "Authorization rejected: Cryptographic signature mismatch (ticket forgery attempt)."

        # Verify exact scope binding
        if meta["action_type"] != action_type:
            return False, f"Authorization rejected: Ticket scope mismatch. Expected {action_type}, got {meta['action_type']}."
        if meta["application_id"] != application_id:
            return False, f"Authorization rejected: Ticket application ID mismatch. Expected {application_id}, got {meta['application_id']}."
        if meta["packet_hash"] != packet_hash:
            return False, "Authorization rejected: Ticket packet version mismatch. Application packet was modified after ticket issuance."

        # Persistent database nonce consumption if db_manager provided
        if db_manager is not None and hasattr(db_manager, "consume_action_nonce_persistently"):
            try:
                db_manager.consume_action_nonce_persistently(
                    ticket_nonce=nonce,
                    key_id=key_id,
                    user_id=session.user_id or 0,
                    action_type=action_type,
                )
            except TicketAlreadyConsumedError as err:
                return False, f"Authorization rejected: {err}"
            except Exception as e:
                logger.error("Persistent nonce check failed: %s", e)
                return False, f"Authorization rejected: Persistent nonce registration failed: {e}"

        # Consume ticket in memory
        del session.issued_tickets[nonce]
        session.consumed_tickets.add(nonce)
        logger.info("Successfully consumed action ticket for %s (Key %s, App #%d, Nonce %s...)", action_type, key_id, application_id, nonce[:8])
        return True, "Action ticket successfully verified and consumed."

    def revoke_session(self, session_id: str) -> bool:
        """Explicitly revokes an active candidate session."""
        if session_id in self._sessions:
            self._sessions[session_id].is_active = False
            logger.info("Revoked candidate session %s...", session_id[:8])
            return True
        return False

    def revoke_user_sessions(self, user_id: int) -> int:
        """Revokes all active sessions belonging to a specific user (e.g. after password reset)."""
        revoked_count = 0
        for session in list(self._sessions.values()):
            if session.user_id == user_id and session.is_active:
                session.is_active = False
                revoked_count += 1
                logger.info("Purged session %s... for User #%d", session.session_id[:8], user_id)
        return revoked_count

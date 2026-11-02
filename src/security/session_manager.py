"""Server-side candidate authentication and session-bound authorization management."""

from dataclasses import dataclass, field
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import time
from typing import Any, Dict, Optional, Set, Tuple

from src.database.exceptions import InvalidSessionError, SessionExpiredError
from src.utils.logger import setup_logger

logger = setup_logger("SessionManager")


@dataclass
class CandidateSession:
    """Represents an active server-side candidate authenticated session."""
    session_id: str
    candidate_id: str
    candidate_name: str
    created_at: float
    expires_at: float
    is_active: bool = True
    issued_tickets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    consumed_tickets: Set[str] = field(default_factory=set)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class SessionManager:
    """Manages candidate authentication, server-side sessions, and cryptographic action tickets."""

    _instance: Optional["SessionManager"] = None

    def __init__(self, server_secret: Optional[bytes] = None):
        self._server_secret = server_secret or secrets.token_bytes(32)
        self._sessions: Dict[str, CandidateSession] = {}

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

    def authenticate_candidate(
        self,
        candidate_id: str,
        candidate_name: str,
        pin_or_secret: Optional[str] = None,
        ttl_seconds: int = 3600,
    ) -> CandidateSession:
        """Establishes an authenticated server-side session for the candidate."""
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

        session_id = secrets.token_hex(24)
        now = time.time()
        session = CandidateSession(
            session_id=session_id,
            candidate_id=clean_id,
            candidate_name=clean_name,
            created_at=now,
            expires_at=now + ttl_seconds,
            is_active=True,
        )
        self._sessions[session_id] = session
        logger.info(f"Authenticated candidate session created: {session_id[:8]}... for {clean_name} ({clean_id})")
        return session

    def validate_session(self, session_id: Optional[str]) -> CandidateSession:
        """Validates that a session exists, is active, and is unexpired."""
        if not session_id or session_id not in self._sessions:
            raise InvalidSessionError("Missing or invalid candidate session.")

        session = self._sessions[session_id]

        if session.is_expired:
            session.is_active = False
            logger.warning(f"Candidate session {session_id[:8]}... expired.")
            raise SessionExpiredError(f"Candidate session {session_id[:8]}... has expired. Re-authentication required.")

        if not session.is_active:
            raise InvalidSessionError("Candidate session has been revoked or deactivated.")

        return session

    def issue_action_ticket(
        self,
        session_id: str,
        action_type: str,
        application_id: int,
        packet_hash: str,
        ttl_seconds: int = 900,
    ) -> str:
        """Issues a single-use cryptographically signed action ticket bound to a specific application and packet version."""
        session = self.validate_session(session_id)

        if not action_type or not packet_hash:
            raise ValueError("action_type and packet_hash are mandatory for ticket issuance.")

        nonce = secrets.token_hex(16)
        timestamp = int(time.time())
        message = f"{session.session_id}:{action_type}:{application_id}:{packet_hash}:{nonce}:{timestamp}"
        signature = hmac.new(self._server_secret, message.encode("utf-8"), hashlib.sha256).hexdigest()

        ticket_str = f"TKT-{nonce}.{timestamp}.{signature}"
        session.issued_tickets[nonce] = {
            "action_type": action_type,
            "application_id": application_id,
            "packet_hash": packet_hash,
            "timestamp": timestamp,
            "ttl": ttl_seconds,
        }
        logger.info(f"Issued single-use action ticket for {action_type} (App #{application_id}, Nonce {nonce[:8]}...)")
        return ticket_str

    def verify_and_consume_action_ticket(
        self,
        session_id: str,
        ticket_str: Optional[str],
        action_type: str,
        application_id: int,
        packet_hash: str,
    ) -> Tuple[bool, str]:
        """Cryptographically verifies and consumes an action ticket.
        
        Guarantees:
        1. Authenticated session validation.
        2. Cryptographic signature authenticity (prevents forgery).
        3. Expiry enforcement.
        4. Scope binding: matches action_type, application_id, and exact packet_hash.
        5. Single-use consumption (prevents replay attacks).
        """
        try:
            session = self.validate_session(session_id)
        except (InvalidSessionError, SessionExpiredError) as e:
            return False, f"Authorization rejected: {e}"

        if not ticket_str or not isinstance(ticket_str, str):
            return False, "Authorization rejected: Missing action ticket."

        # Explicitly reject hardcoded dummy constants
        if ticket_str in ("CANDIDATE_VERIFIED_DASHBOARD_APPROVAL", "CANDIDATE_VERIFIED_MANUAL_SUBMISSION"):
            return False, "Authorization rejected: Static constant token rejected. Authenticated session ticket required."

        if not ticket_str.startswith("TKT-") or "." not in ticket_str:
            return False, "Authorization rejected: Malformed action ticket."

        parts = ticket_str[4:].split(".")
        if len(parts) != 3:
            return False, "Authorization rejected: Invalid action ticket structure."

        nonce, ts_str, signature = parts
        try:
            timestamp = int(ts_str)
        except ValueError:
            return False, "Authorization rejected: Corrupt timestamp in action ticket."

        # Check for replay
        if nonce in session.consumed_tickets:
            logger.warning(f"Replay attack detected: Ticket nonce {nonce[:8]}... already consumed.")
            return False, "Authorization rejected: Replay attack detected. Action ticket has already been used."

        if nonce not in session.issued_tickets:
            return False, "Authorization rejected: Unrecognized or unissued action ticket."

        meta = session.issued_tickets[nonce]

        # Check expiry
        now = time.time()
        if now - timestamp > meta["ttl"]:
            return False, "Authorization rejected: Action ticket has expired."

        # Verify HMAC cryptographic signature
        expected_message = f"{session.session_id}:{action_type}:{application_id}:{packet_hash}:{nonce}:{timestamp}"
        expected_sig = hmac.new(self._server_secret, expected_message.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            logger.error("Action ticket signature forgery attempt detected.")
            return False, "Authorization rejected: Cryptographic signature mismatch (ticket forgery attempt)."

        # Verify exact scope binding
        if meta["action_type"] != action_type:
            return False, f"Authorization rejected: Ticket scope mismatch. Expected {action_type}, got {meta['action_type']}."
        if meta["application_id"] != application_id:
            return False, f"Authorization rejected: Ticket application ID mismatch. Expected {application_id}, got {meta['application_id']}."
        if meta["packet_hash"] != packet_hash:
            return False, "Authorization rejected: Ticket packet version mismatch. Application packet was modified after ticket issuance."

        # Consume ticket
        del session.issued_tickets[nonce]
        session.consumed_tickets.add(nonce)
        logger.info(f"Successfully consumed action ticket for {action_type} (App #{application_id}, Nonce {nonce[:8]}...)")
        return True, "Action ticket successfully verified and consumed."

    def revoke_session(self, session_id: str) -> bool:
        """Explicitly revokes an active candidate session."""
        if session_id in self._sessions:
            self._sessions[session_id].is_active = False
            logger.info(f"Revoked candidate session {session_id[:8]}...")
            return True
        return False

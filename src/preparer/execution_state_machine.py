"""Application Execution State Machine (IAGH Architecture).

Implements the persistent, validated state machine governing external ATS
browser automation, intermediate gate handling, user interactions, and autofill resumption.

Lifecycle States:
- PORTAL_OPENED
- COMPANION_CONNECTED
- PAGE_ANALYZING
- GATE_DETECTED
- WAITING_FOR_USER
- USER_ACTION_DETECTED
- NAVIGATION_IN_PROGRESS
- PAGE_TRANSITION_DETECTED
- PAGE_REANALYZING
- AUTHENTICATION_REQUIRED
- SECURITY_CHALLENGE_REQUIRED
- APPLICATION_FORM_DETECTED
- AUTOFILL_RESUMED
- RESUME_UPLOADED
- ATS_PARSING
- FIELDS_POPULATED
- FIELDS_VERIFIED
- READY_FOR_HUMAN_REVIEW
- USER_DECLINED
- EXECUTION_FAILED
- EXECUTION_TIMED_OUT

Operational Invariants:
1. Every state transition is validated on the backend against strict transition rules.
2. Every transition records execution_id, application_id, timestamp, event_source, and validation_result.
3. State transitions are persisted to SQLite (autofill_execution_sessions) to survive browser reloads or process restarts.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from src.database.db_manager import DatabaseManager
from src.database.exceptions import SecurityAuthorizationError
from src.utils.logger import setup_logger

logger = setup_logger("ApplicationExecutionStateMachine")


class ExecutionState(str, Enum):
    PORTAL_OPENED = "PORTAL_OPENED"
    COMPANION_CONNECTED = "COMPANION_CONNECTED"
    PAGE_ANALYZING = "PAGE_ANALYZING"
    GATE_DETECTED = "GATE_DETECTED"
    WAITING_FOR_USER = "WAITING_FOR_USER"
    USER_ACTION_DETECTED = "USER_ACTION_DETECTED"
    NAVIGATION_IN_PROGRESS = "NAVIGATION_IN_PROGRESS"
    PAGE_TRANSITION_DETECTED = "PAGE_TRANSITION_DETECTED"
    PAGE_REANALYZING = "PAGE_REANALYZING"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    SECURITY_CHALLENGE_REQUIRED = "SECURITY_CHALLENGE_REQUIRED"
    APPLICATION_FORM_DETECTED = "APPLICATION_FORM_DETECTED"
    AUTOFILL_RESUMED = "AUTOFILL_RESUMED"
    RESUME_UPLOADED = "RESUME_UPLOADED"
    ATS_PARSING = "ATS_PARSING"
    FIELDS_POPULATED = "FIELDS_POPULATED"
    FIELDS_VERIFIED = "FIELDS_VERIFIED"
    READY_FOR_HUMAN_REVIEW = "READY_FOR_HUMAN_REVIEW"
    USER_DECLINED = "USER_DECLINED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTION_TIMED_OUT = "EXECUTION_TIMED_OUT"


@dataclass
class StateTransitionRecord:
    """Immutable audit record of an execution state transition."""
    execution_id: str
    application_id: int
    previous_state: Optional[str]
    new_state: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_source: str = "BACKEND"  # COMPANION, PLAYWRIGHT, BACKEND, USER
    validation_result: str = "VALID"  # VALID, FORCED, RECOVERY
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ApplicationExecutionStateMachine:
    """Authoritative state machine orchestrating external employer application lifecycles."""

    # Explicit allowed transitions map
    VALID_TRANSITIONS: Dict[ExecutionState, Set[ExecutionState]] = {
        ExecutionState.PORTAL_OPENED: {
            ExecutionState.COMPANION_CONNECTED,
            ExecutionState.PAGE_ANALYZING,
            ExecutionState.GATE_DETECTED,
            ExecutionState.WAITING_FOR_USER,
            ExecutionState.USER_ACTION_DETECTED,
            ExecutionState.APPLICATION_FORM_DETECTED,
            ExecutionState.AUTHENTICATION_REQUIRED,
            ExecutionState.SECURITY_CHALLENGE_REQUIRED,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.COMPANION_CONNECTED: {
            ExecutionState.PAGE_ANALYZING,
            ExecutionState.GATE_DETECTED,
            ExecutionState.APPLICATION_FORM_DETECTED,
            ExecutionState.AUTHENTICATION_REQUIRED,
            ExecutionState.SECURITY_CHALLENGE_REQUIRED,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.PAGE_ANALYZING: {
            ExecutionState.GATE_DETECTED,
            ExecutionState.WAITING_FOR_USER,
            ExecutionState.AUTHENTICATION_REQUIRED,
            ExecutionState.SECURITY_CHALLENGE_REQUIRED,
            ExecutionState.APPLICATION_FORM_DETECTED,
            ExecutionState.AUTOFILL_RESUMED,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.GATE_DETECTED: {
            ExecutionState.WAITING_FOR_USER,
            ExecutionState.USER_ACTION_DETECTED,
            ExecutionState.APPLICATION_FORM_DETECTED,
            ExecutionState.USER_DECLINED,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.WAITING_FOR_USER: {
            ExecutionState.USER_ACTION_DETECTED,
            ExecutionState.NAVIGATION_IN_PROGRESS,
            ExecutionState.PAGE_TRANSITION_DETECTED,
            ExecutionState.PAGE_REANALYZING,
            ExecutionState.USER_DECLINED,
            ExecutionState.APPLICATION_FORM_DETECTED,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.USER_ACTION_DETECTED: {
            ExecutionState.GATE_DETECTED,
            ExecutionState.WAITING_FOR_USER,
            ExecutionState.AUTHENTICATION_REQUIRED,
            ExecutionState.SECURITY_CHALLENGE_REQUIRED,
            ExecutionState.NAVIGATION_IN_PROGRESS,
            ExecutionState.PAGE_TRANSITION_DETECTED,
            ExecutionState.PAGE_REANALYZING,
            ExecutionState.PAGE_ANALYZING,
            ExecutionState.APPLICATION_FORM_DETECTED,
            ExecutionState.AUTOFILL_RESUMED,
            ExecutionState.USER_DECLINED,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.NAVIGATION_IN_PROGRESS: {
            ExecutionState.PAGE_TRANSITION_DETECTED,
            ExecutionState.PAGE_REANALYZING,
            ExecutionState.COMPANION_CONNECTED,
            ExecutionState.PAGE_ANALYZING,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.PAGE_TRANSITION_DETECTED: {
            ExecutionState.PAGE_REANALYZING,
            ExecutionState.PAGE_ANALYZING,
            ExecutionState.COMPANION_CONNECTED,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.PAGE_REANALYZING: {
            ExecutionState.GATE_DETECTED,
            ExecutionState.WAITING_FOR_USER,
            ExecutionState.AUTHENTICATION_REQUIRED,
            ExecutionState.SECURITY_CHALLENGE_REQUIRED,
            ExecutionState.APPLICATION_FORM_DETECTED,
            ExecutionState.AUTOFILL_RESUMED,
            ExecutionState.USER_DECLINED,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.AUTHENTICATION_REQUIRED: {
            ExecutionState.WAITING_FOR_USER,
            ExecutionState.USER_ACTION_DETECTED,
            ExecutionState.NAVIGATION_IN_PROGRESS,
            ExecutionState.PAGE_TRANSITION_DETECTED,
            ExecutionState.PAGE_REANALYZING,
            ExecutionState.APPLICATION_FORM_DETECTED,
            ExecutionState.USER_DECLINED,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.SECURITY_CHALLENGE_REQUIRED: {
            ExecutionState.WAITING_FOR_USER,
            ExecutionState.USER_ACTION_DETECTED,
            ExecutionState.NAVIGATION_IN_PROGRESS,
            ExecutionState.PAGE_TRANSITION_DETECTED,
            ExecutionState.PAGE_REANALYZING,
            ExecutionState.APPLICATION_FORM_DETECTED,
            ExecutionState.USER_DECLINED,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.APPLICATION_FORM_DETECTED: {
            ExecutionState.AUTOFILL_RESUMED,
            ExecutionState.RESUME_UPLOADED,
            ExecutionState.ATS_PARSING,
            ExecutionState.FIELDS_POPULATED,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.AUTOFILL_RESUMED: {
            ExecutionState.RESUME_UPLOADED,
            ExecutionState.ATS_PARSING,
            ExecutionState.FIELDS_POPULATED,
            ExecutionState.FIELDS_VERIFIED,
            ExecutionState.READY_FOR_HUMAN_REVIEW,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.RESUME_UPLOADED: {
            ExecutionState.ATS_PARSING,
            ExecutionState.FIELDS_POPULATED,
            ExecutionState.FIELDS_VERIFIED,
            ExecutionState.READY_FOR_HUMAN_REVIEW,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.ATS_PARSING: {
            ExecutionState.FIELDS_POPULATED,
            ExecutionState.FIELDS_VERIFIED,
            ExecutionState.READY_FOR_HUMAN_REVIEW,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.FIELDS_POPULATED: {
            ExecutionState.FIELDS_VERIFIED,
            ExecutionState.READY_FOR_HUMAN_REVIEW,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        ExecutionState.FIELDS_VERIFIED: {
            ExecutionState.READY_FOR_HUMAN_REVIEW,
            ExecutionState.EXECUTION_FAILED,
            ExecutionState.EXECUTION_TIMED_OUT,
        },
        # Terminal states (cannot transition further except on full reset/replay)
        ExecutionState.READY_FOR_HUMAN_REVIEW: set(),
        ExecutionState.USER_DECLINED: set(),
        ExecutionState.EXECUTION_FAILED: set(),
        ExecutionState.EXECUTION_TIMED_OUT: set(),
    }

    _lock: threading.Lock = threading.Lock()

    def __init__(self, db_manager: Optional[DatabaseManager] = None) -> None:
        self.db = db_manager or DatabaseManager()

    def is_transition_valid(self, current_state: ExecutionState, new_state: ExecutionState) -> bool:
        """Evaluates whether a state transition is permitted by the state graph."""
        if current_state == new_state:
            return True
        allowed = self.VALID_TRANSITIONS.get(current_state, set())
        return new_state in allowed

    def transition(
        self,
        execution_id: str,
        new_state: ExecutionState,
        event_source: str = "BACKEND",
        message: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> StateTransitionRecord:
        """Executes an authoritative state transition with validation and persistent logging."""
        with self._lock:
            # 1. Load active session from SQLite or in-memory
            session = self.db.get_autofill_execution_session(execution_id)
            if not session:
                raise SecurityAuthorizationError(f"No execution session found for execution_id '{execution_id}'.")

            current_str = session.get("current_state", ExecutionState.PORTAL_OPENED.value)
            try:
                current_state = ExecutionState(current_str)
            except ValueError:
                current_state = ExecutionState.PORTAL_OPENED

            # 2. Validate transition
            val_result = "VALID"
            if not force and not self.is_transition_valid(current_state, new_state):
                logger.warning(
                    f"Invalid state transition attempted: {current_state.value} -> {new_state.value} for execution {execution_id}"
                )
                raise SecurityAuthorizationError(
                    f"Illegal state transition from '{current_state.value}' to '{new_state.value}'."
                )
            elif force:
                val_result = "FORCED"

            # 3. Create transition record
            now_iso = datetime.now(timezone.utc).isoformat()
            meta = metadata or {}
            transition_rec = StateTransitionRecord(
                execution_id=execution_id,
                application_id=session["application_id"],
                previous_state=current_state.value,
                new_state=new_state.value,
                timestamp=now_iso,
                event_source=event_source,
                validation_result=val_result,
                message=message,
                metadata=meta,
            )

            # 4. Update session history and metadata
            history = session.get("state_history", [])
            history.append(transition_rec.to_dict())
            session_meta = session.get("metadata", {})
            session_meta.update(meta)

            # Update session record
            session["current_state"] = new_state.value
            session["previous_state"] = current_state.value
            session["state_history"] = history
            session["metadata"] = session_meta

            # Update specific gate info if provided in metadata
            if "gate_category" in meta:
                session["gate_category"] = meta["gate_category"]
            if "gate_type" in meta:
                session["gate_type"] = meta["gate_type"]
            if "is_blocking" in meta:
                session["is_blocking"] = 1 if meta["is_blocking"] else 0
            if "required_user_action" in meta:
                session["required_user_action"] = meta["required_user_action"]

            # Save to SQLite
            self.db.save_autofill_execution_session(session)

            logger.info(
                f"Execution #{execution_id} transitioned: {current_state.value} -> {new_state.value} [{event_source}] {message}"
            )
            return transition_rec

    def get_current_state(self, execution_id: str) -> Optional[ExecutionState]:
        """Retrieves the current validated state of an execution session."""
        session = self.db.get_autofill_execution_session(execution_id)
        if not session:
            return None
        try:
            return ExecutionState(session.get("current_state", ExecutionState.PORTAL_OPENED.value))
        except ValueError:
            return None

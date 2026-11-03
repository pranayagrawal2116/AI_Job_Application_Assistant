"""Application Lifecycle State Machine (Phase 7.2).

Defines the authoritative lifecycle transition matrix, validates status transitions,
enforces terminal state rules, handles legacy status aliases, and determines audit event types.
"""

from typing import Dict, List, Set, Tuple, Union

from src.database.exceptions import (
    InvalidStatusError,
    InvalidStatusTransitionError,
    SecurityAuthorizationError,
)
from src.database.models import ApplicationStatus


class ApplicationStateMachine:
    """Authoritative application lifecycle state machine governing all status transitions.

    Decoupled from Streamlit UI and raw database connections.
    """

    # Canonical 12 universal lifecycle statuses
    UNIVERSAL_STATUSES: Set[ApplicationStatus] = {
        ApplicationStatus.DRAFT,
        ApplicationStatus.PREPARING,
        ApplicationStatus.READY_FOR_REVIEW,
        ApplicationStatus.APPROVED,
        ApplicationStatus.SUBMITTED,
        ApplicationStatus.IN_PROGRESS,
        ApplicationStatus.ASSESSMENT,
        ApplicationStatus.INTERVIEW,
        ApplicationStatus.OFFER,
        ApplicationStatus.REJECTED,
        ApplicationStatus.WITHDRAWN,
        ApplicationStatus.CLOSED,
    }

    # Case-insensitive legacy mapping to canonical universal statuses
    LEGACY_STATUS_MAP: Dict[str, ApplicationStatus] = {
        "discovered": ApplicationStatus.DRAFT,
        "draft": ApplicationStatus.DRAFT,
        "under review": ApplicationStatus.PREPARING,
        "under_review": ApplicationStatus.PREPARING,
        "shortlisted": ApplicationStatus.PREPARING,
        "preparing": ApplicationStatus.PREPARING,
        "application prepared": ApplicationStatus.READY_FOR_REVIEW,
        "application_prepared": ApplicationStatus.READY_FOR_REVIEW,
        "ready_for_review": ApplicationStatus.READY_FOR_REVIEW,
        "awaiting approval": ApplicationStatus.APPROVED,
        "awaiting_approval": ApplicationStatus.APPROVED,
        "approved": ApplicationStatus.APPROVED,
        "applied": ApplicationStatus.SUBMITTED,
        "submitted": ApplicationStatus.SUBMITTED,
        "in_progress": ApplicationStatus.IN_PROGRESS,
        "in progress": ApplicationStatus.IN_PROGRESS,
        "assessment": ApplicationStatus.ASSESSMENT,
        "interview": ApplicationStatus.INTERVIEW,
        "offer": ApplicationStatus.OFFER,
        "rejected": ApplicationStatus.REJECTED,
        "withdrawn": ApplicationStatus.WITHDRAWN,
        "closed": ApplicationStatus.CLOSED,
    }

    # Explicit transition matrix: every valid transition is strictly enumerated
    ALLOWED_TRANSITIONS: Dict[ApplicationStatus, Set[ApplicationStatus]] = {
        ApplicationStatus.DRAFT: {
            ApplicationStatus.PREPARING,
            ApplicationStatus.WITHDRAWN,
            ApplicationStatus.CLOSED,
        },
        ApplicationStatus.PREPARING: {
            ApplicationStatus.READY_FOR_REVIEW,
            ApplicationStatus.DRAFT,
            ApplicationStatus.WITHDRAWN,
        },
        ApplicationStatus.READY_FOR_REVIEW: {
            ApplicationStatus.APPROVED,
            ApplicationStatus.PREPARING,
            ApplicationStatus.WITHDRAWN,
        },
        ApplicationStatus.APPROVED: {
            ApplicationStatus.SUBMITTED,
            ApplicationStatus.READY_FOR_REVIEW,
            ApplicationStatus.WITHDRAWN,
        },
        ApplicationStatus.SUBMITTED: {
            ApplicationStatus.IN_PROGRESS,
            ApplicationStatus.ASSESSMENT,
            ApplicationStatus.INTERVIEW,
            ApplicationStatus.REJECTED,
            ApplicationStatus.WITHDRAWN,
        },
        ApplicationStatus.IN_PROGRESS: {
            ApplicationStatus.ASSESSMENT,
            ApplicationStatus.INTERVIEW,
            ApplicationStatus.OFFER,
            ApplicationStatus.REJECTED,
            ApplicationStatus.WITHDRAWN,
        },
        ApplicationStatus.ASSESSMENT: {
            ApplicationStatus.INTERVIEW,
            ApplicationStatus.OFFER,
            ApplicationStatus.REJECTED,
            ApplicationStatus.WITHDRAWN,
        },
        ApplicationStatus.INTERVIEW: {
            ApplicationStatus.ASSESSMENT,
            ApplicationStatus.OFFER,
            ApplicationStatus.REJECTED,
            ApplicationStatus.WITHDRAWN,
        },
        ApplicationStatus.OFFER: {
            ApplicationStatus.CLOSED,
            ApplicationStatus.REJECTED,
            ApplicationStatus.WITHDRAWN,
        },
        ApplicationStatus.REJECTED: {
            ApplicationStatus.CLOSED,
            ApplicationStatus.IN_PROGRESS,  # Re-opening
        },
        ApplicationStatus.WITHDRAWN: {
            ApplicationStatus.CLOSED,
            ApplicationStatus.IN_PROGRESS,  # Re-opening
        },
        ApplicationStatus.CLOSED: {
            ApplicationStatus.IN_PROGRESS,  # Re-opening
        },
    }

    # Statuses requiring dedicated cryptographic or verification gates
    GATE_PROTECTED_TARGETS: Set[ApplicationStatus] = {
        ApplicationStatus.APPROVED,
        ApplicationStatus.SUBMITTED,
    }

    # Conclusion / terminal statuses
    TERMINAL_STATUSES: Set[ApplicationStatus] = {
        ApplicationStatus.REJECTED,
        ApplicationStatus.WITHDRAWN,
        ApplicationStatus.CLOSED,
    }

    # Specific pairwise event types
    SPECIFIC_EVENT_TYPES: Dict[Tuple[ApplicationStatus, ApplicationStatus], str] = {
        (ApplicationStatus.DRAFT, ApplicationStatus.PREPARING): "APPLICATION_PREPARATION_STARTED",
        (ApplicationStatus.PREPARING, ApplicationStatus.READY_FOR_REVIEW): "APPLICATION_READY_FOR_REVIEW",
        (ApplicationStatus.READY_FOR_REVIEW, ApplicationStatus.APPROVED): "PACKET_HUMAN_APPROVED",
        (ApplicationStatus.APPROVED, ApplicationStatus.SUBMITTED): "SUBMISSION_CONFIRMED",
    }

    @classmethod
    def normalize_status(cls, status: Union[str, ApplicationStatus]) -> ApplicationStatus:
        """Normalizes any string, legacy alias, or enum to its canonical ApplicationStatus.

        Raises InvalidStatusError if the status is unrecognized.
        """
        if isinstance(status, ApplicationStatus):
            # Check if it's already universal or legacy enum member
            clean_val = status.value.strip().lower()
        elif isinstance(status, str):
            clean_val = status.strip().lower()
        else:
            raise InvalidStatusError(str(status), ApplicationStatus.universal_statuses())

        if clean_val in cls.LEGACY_STATUS_MAP:
            return cls.LEGACY_STATUS_MAP[clean_val]

        # Check against all ApplicationStatus enum values
        for member in ApplicationStatus:
            if member.value.lower() == clean_val or member.name.lower() == clean_val:
                if member in cls.UNIVERSAL_STATUSES:
                    return member
                val_lower = member.value.lower()
                if val_lower in cls.LEGACY_STATUS_MAP:
                    return cls.LEGACY_STATUS_MAP[val_lower]

        raise InvalidStatusError(str(status), ApplicationStatus.universal_statuses())

    @classmethod
    def is_valid_transition(
        cls,
        current_status: Union[str, ApplicationStatus],
        new_status: Union[str, ApplicationStatus],
        is_gate_authorized: bool = False,
    ) -> bool:
        """Returns True if the transition from current_status to new_status is permitted."""
        try:
            cls.validate_transition(current_status, new_status, is_gate_authorized=is_gate_authorized)
            return True
        except (InvalidStatusError, InvalidStatusTransitionError, SecurityAuthorizationError):
            return False

    @classmethod
    def validate_transition(
        cls,
        current_status: Union[str, ApplicationStatus],
        new_status: Union[str, ApplicationStatus],
        is_gate_authorized: bool = False,
    ) -> None:
        """Validates that a transition from current_status to new_status is permitted.

        Raises:
            InvalidStatusError: If current or new status is unrecognized.
            InvalidStatusTransitionError: If the transition is not present in the transition matrix.
            SecurityAuthorizationError: If attempting to transition to a gate-protected status
                (APPROVED or SUBMITTED) without gate authorization.
        """
        curr = cls.normalize_status(current_status)
        target = cls.normalize_status(new_status)

        allowed = cls.ALLOWED_TRANSITIONS.get(curr, set())
        allowed_str_list = sorted([s.value for s in allowed])

        # Self-transitions are not valid state advances
        if curr == target:
            raise InvalidStatusTransitionError(curr.value, target.value, allowed_str_list)

        if target not in allowed:
            raise InvalidStatusTransitionError(curr.value, target.value, allowed_str_list)

        # Gate-protected statuses require dedicated workflow authorization
        if target in cls.GATE_PROTECTED_TARGETS and not is_gate_authorized:
            if target == ApplicationStatus.APPROVED:
                raise SecurityAuthorizationError(
                    f"Transition to '{target.value}' requires explicit human packet approval via HumanApprovalGate, "
                    "not generic status updates."
                )
            if target == ApplicationStatus.SUBMITTED:
                raise SecurityAuthorizationError(
                    f"Transition to '{target.value}' requires candidate manual submission confirmation with "
                    "an action ticket, not generic status updates."
                )

    @classmethod
    def get_allowed_transitions(
        cls,
        current_status: Union[str, ApplicationStatus],
        is_gate_authorized: bool = False,
    ) -> List[str]:
        """Returns the list of valid next status strings for the given current status."""
        curr = cls.normalize_status(current_status)
        targets = cls.ALLOWED_TRANSITIONS.get(curr, set())
        if not is_gate_authorized:
            targets = {t for t in targets if t not in cls.GATE_PROTECTED_TARGETS}
        return sorted([s.value for s in targets])

    @classmethod
    def is_terminal_status(cls, status: Union[str, ApplicationStatus]) -> bool:
        """Returns True if the status represents a conclusion or terminal state (REJECTED, WITHDRAWN, CLOSED)."""
        curr = cls.normalize_status(status)
        return curr in cls.TERMINAL_STATUSES

    @classmethod
    def is_reopening_transition(
        cls,
        current_status: Union[str, ApplicationStatus],
        new_status: Union[str, ApplicationStatus],
    ) -> bool:
        """Returns True if this is an explicit re-opening transition from a terminal state to IN_PROGRESS."""
        curr = cls.normalize_status(current_status)
        target = cls.normalize_status(new_status)
        return curr in cls.TERMINAL_STATUSES and target == ApplicationStatus.IN_PROGRESS

    @classmethod
    def get_transition_event_type(
        cls,
        current_status: Union[str, ApplicationStatus],
        new_status: Union[str, ApplicationStatus],
    ) -> str:
        """Determines the appropriate audit event type for a valid status transition."""
        curr = cls.normalize_status(current_status)
        target = cls.normalize_status(new_status)

        pair = (curr, target)
        if pair in cls.SPECIFIC_EVENT_TYPES:
            return cls.SPECIFIC_EVENT_TYPES[pair]

        if cls.is_reopening_transition(curr, target):
            return "APPLICATION_REOPENED"

        if target == ApplicationStatus.WITHDRAWN:
            return "APPLICATION_WITHDRAWN"

        if target == ApplicationStatus.REJECTED:
            return "REJECTION_RECORDED"

        if target == ApplicationStatus.OFFER:
            return "OFFER_RECEIVED"

        if target == ApplicationStatus.ASSESSMENT:
            return "ASSESSMENT_MILESTONE_LOGGED"

        if target == ApplicationStatus.INTERVIEW:
            return "INTERVIEW_MILESTONE_LOGGED"

        if target == ApplicationStatus.CLOSED:
            return "APPLICATION_CLOSED"

        if target == ApplicationStatus.IN_PROGRESS:
            return "STATUS_CHANGED_TO_IN_PROGRESS"

        return f"STATUS_CHANGED_TO_{target.value}"

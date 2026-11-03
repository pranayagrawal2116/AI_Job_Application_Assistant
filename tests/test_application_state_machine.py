"""Comprehensive tests for ApplicationStateMachine (Phase 7.2).

Covers:
1. Universal status normalization and legacy alias mapping.
2. Complete valid transition matrix (all allowed transitions).
3. Complete invalid transition matrix (all disallowed transitions across 12x12 state space).
4. Gate protection enforcement (APPROVED and SUBMITTED require is_gate_authorized=True).
5. Terminal state classification (REJECTED, WITHDRAWN, CLOSED).
6. Re-opening behavior from terminal states to IN_PROGRESS.
7. Allowed transitions enumeration.
8. Audit event type determination for every permitted transition.
"""

import unittest

from src.database.exceptions import (
    InvalidStatusError,
    InvalidStatusTransitionError,
    SecurityAuthorizationError,
)
from src.database.models import ApplicationStatus
from src.lifecycle.state_machine import ApplicationStateMachine


class TestApplicationStateMachine(unittest.TestCase):
    """Test suite for ApplicationStateMachine."""

    def test_normalize_universal_statuses(self):
        """All 12 universal statuses normalize to themselves regardless of case or whitespace."""
        for status in ApplicationStatus.universal_statuses():
            self.assertEqual(
                ApplicationStateMachine.normalize_status(status),
                ApplicationStatus(status),
            )
            self.assertEqual(
                ApplicationStateMachine.normalize_status(status.lower()),
                ApplicationStatus(status),
            )
            self.assertEqual(
                ApplicationStateMachine.normalize_status(f"  {status.lower()}  "),
                ApplicationStatus(status),
            )

    def test_normalize_legacy_aliases(self):
        """Legacy status strings correctly map to their canonical universal equivalents."""
        mappings = {
            "Discovered": ApplicationStatus.DRAFT,
            "discovered": ApplicationStatus.DRAFT,
            "Under Review": ApplicationStatus.PREPARING,
            "under review": ApplicationStatus.PREPARING,
            "under_review": ApplicationStatus.PREPARING,
            "Shortlisted": ApplicationStatus.PREPARING,
            "shortlisted": ApplicationStatus.PREPARING,
            "Application Prepared": ApplicationStatus.READY_FOR_REVIEW,
            "application prepared": ApplicationStatus.READY_FOR_REVIEW,
            "application_prepared": ApplicationStatus.READY_FOR_REVIEW,
            "Awaiting Approval": ApplicationStatus.APPROVED,
            "awaiting approval": ApplicationStatus.APPROVED,
            "awaiting_approval": ApplicationStatus.APPROVED,
            "Applied": ApplicationStatus.SUBMITTED,
            "applied": ApplicationStatus.SUBMITTED,
            "Interview": ApplicationStatus.INTERVIEW,
            "interview": ApplicationStatus.INTERVIEW,
            "Rejected": ApplicationStatus.REJECTED,
            "rejected": ApplicationStatus.REJECTED,
            "Withdrawn": ApplicationStatus.WITHDRAWN,
            "withdrawn": ApplicationStatus.WITHDRAWN,
        }
        for legacy_str, expected in mappings.items():
            self.assertEqual(
                ApplicationStateMachine.normalize_status(legacy_str),
                expected,
                f"Failed for legacy string: {legacy_str}",
            )

    def test_normalize_unknown_status_raises(self):
        """Unknown status strings raise InvalidStatusError with available options."""
        for invalid in ["UNKNOWN", "FOOBAR", "", "   ", "NOT_A_STATUS", "123"]:
            with self.assertRaises(InvalidStatusError) as ctx:
                ApplicationStateMachine.normalize_status(invalid)
            self.assertIn("Invalid status", str(ctx.exception))

    def test_all_allowed_transitions_succeed(self):
        """Every non-gate-protected allowed transition succeeds in generic validation."""
        for current_status, allowed_targets in ApplicationStateMachine.ALLOWED_TRANSITIONS.items():
            for target_status in allowed_targets:
                if target_status in ApplicationStateMachine.GATE_PROTECTED_TARGETS:
                    # Gate-protected statuses strictly reject generic transition
                    self.assertFalse(
                        ApplicationStateMachine.is_valid_transition(current_status, target_status),
                        f"Expected {current_status.value} -> {target_status.value} to be gate-protected",
                    )
                    with self.assertRaises(SecurityAuthorizationError):
                        ApplicationStateMachine.validate_transition(current_status, target_status)
                else:
                    self.assertTrue(
                        ApplicationStateMachine.is_valid_transition(current_status, target_status),
                        f"Expected {current_status.value} -> {target_status.value} to be valid",
                    )
                    ApplicationStateMachine.validate_transition(current_status, target_status)

    def test_disallowed_transitions_across_full_matrix(self):
        """Every transition not in ALLOWED_TRANSITIONS must be rejected."""
        all_statuses = list(ApplicationStateMachine.UNIVERSAL_STATUSES)
        for curr in all_statuses:
            allowed = ApplicationStateMachine.ALLOWED_TRANSITIONS.get(curr, set())
            for target in all_statuses:
                if target not in allowed:
                    self.assertFalse(
                        ApplicationStateMachine.is_valid_transition(curr, target),
                        f"Expected {curr.value} -> {target.value} to be invalid",
                    )
                    with self.assertRaises(InvalidStatusTransitionError) as ctx:
                        ApplicationStateMachine.validate_transition(curr, target)
                    self.assertIn(f"from '{curr.value}' to '{target.value}'", str(ctx.exception))

    def test_gate_protected_transition_to_approved(self):
        """Transition to APPROVED cannot be bypassed by boolean flags."""
        # READY_FOR_REVIEW -> APPROVED is structurally in matrix, but gate-protected
        self.assertFalse(
            ApplicationStateMachine.is_valid_transition(
                ApplicationStatus.READY_FOR_REVIEW, ApplicationStatus.APPROVED
            )
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            ApplicationStateMachine.validate_transition(
                ApplicationStatus.READY_FOR_REVIEW, ApplicationStatus.APPROVED
            )
        self.assertIn("gate-protected", str(ctx.exception).lower())

        # Passing is_gate_authorized=True CANNOT bypass the gate!
        self.assertFalse(
            ApplicationStateMachine.is_valid_transition(
                ApplicationStatus.READY_FOR_REVIEW, ApplicationStatus.APPROVED, is_gate_authorized=True
            )
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            ApplicationStateMachine.validate_transition(
                ApplicationStatus.READY_FOR_REVIEW, ApplicationStatus.APPROVED, is_gate_authorized=True
            )
        self.assertIn("cannot bypass", str(ctx.exception).lower())

    def test_gate_protected_transition_to_submitted(self):
        """Transition to SUBMITTED cannot be bypassed by boolean flags."""
        # APPROVED -> SUBMITTED is structurally in matrix, but gate-protected
        self.assertFalse(
            ApplicationStateMachine.is_valid_transition(
                ApplicationStatus.APPROVED, ApplicationStatus.SUBMITTED
            )
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            ApplicationStateMachine.validate_transition(
                ApplicationStatus.APPROVED, ApplicationStatus.SUBMITTED
            )
        self.assertIn("gate-protected", str(ctx.exception).lower())

        # Passing is_gate_authorized=True CANNOT bypass the gate!
        self.assertFalse(
            ApplicationStateMachine.is_valid_transition(
                ApplicationStatus.APPROVED, ApplicationStatus.SUBMITTED, is_gate_authorized=True
            )
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            ApplicationStateMachine.validate_transition(
                ApplicationStatus.APPROVED, ApplicationStatus.SUBMITTED, is_gate_authorized=True
            )
        self.assertIn("cannot bypass", str(ctx.exception).lower())

    def test_terminal_statuses(self):
        """REJECTED, WITHDRAWN, and CLOSED are correctly identified as terminal statuses."""
        terminal_list = [
            ApplicationStatus.REJECTED,
            ApplicationStatus.WITHDRAWN,
            ApplicationStatus.CLOSED,
        ]
        for st in terminal_list:
            self.assertTrue(ApplicationStateMachine.is_terminal_status(st))
            self.assertTrue(ApplicationStateMachine.is_terminal_status(st.value))

        non_terminal_list = [
            ApplicationStatus.DRAFT,
            ApplicationStatus.PREPARING,
            ApplicationStatus.READY_FOR_REVIEW,
            ApplicationStatus.APPROVED,
            ApplicationStatus.SUBMITTED,
            ApplicationStatus.IN_PROGRESS,
            ApplicationStatus.ASSESSMENT,
            ApplicationStatus.INTERVIEW,
            ApplicationStatus.OFFER,
        ]
        for st in non_terminal_list:
            self.assertFalse(ApplicationStateMachine.is_terminal_status(st))
            self.assertFalse(ApplicationStateMachine.is_terminal_status(st.value))

    def test_reopening_transitions_from_terminal_states(self):
        """REJECTED, WITHDRAWN, and CLOSED can only be re-opened to IN_PROGRESS."""
        for term_status in [ApplicationStatus.REJECTED, ApplicationStatus.WITHDRAWN, ApplicationStatus.CLOSED]:
            # Can transition to IN_PROGRESS (reopening)
            self.assertTrue(
                ApplicationStateMachine.is_valid_transition(term_status, ApplicationStatus.IN_PROGRESS)
            )
            self.assertTrue(
                ApplicationStateMachine.is_reopening_transition(term_status, ApplicationStatus.IN_PROGRESS)
            )
            self.assertEqual(
                ApplicationStateMachine.get_transition_event_type(term_status, ApplicationStatus.IN_PROGRESS),
                "APPLICATION_REOPENED",
            )

            # Cannot transition to other active states
            for invalid_target in [
                ApplicationStatus.DRAFT,
                ApplicationStatus.PREPARING,
                ApplicationStatus.READY_FOR_REVIEW,
                ApplicationStatus.APPROVED,
                ApplicationStatus.SUBMITTED,
                ApplicationStatus.ASSESSMENT,
                ApplicationStatus.INTERVIEW,
                ApplicationStatus.OFFER,
            ]:
                self.assertFalse(
                    ApplicationStateMachine.is_valid_transition(term_status, invalid_target)
                )

    def test_get_allowed_transitions_filtering(self):
        """get_allowed_transitions filters gate-protected statuses unless include_gate_protected=True."""
        # READY_FOR_REVIEW without gate authorization excludes APPROVED
        allowed_unauth = ApplicationStateMachine.get_allowed_transitions(
            ApplicationStatus.READY_FOR_REVIEW
        )
        self.assertNotIn("APPROVED", allowed_unauth)
        self.assertIn("PREPARING", allowed_unauth)
        self.assertIn("WITHDRAWN", allowed_unauth)

        # READY_FOR_REVIEW with include_gate_protected=True includes APPROVED
        allowed_auth = ApplicationStateMachine.get_allowed_transitions(
            ApplicationStatus.READY_FOR_REVIEW, include_gate_protected=True
        )
        self.assertIn("APPROVED", allowed_auth)

        # APPROVED without gate authorization excludes SUBMITTED
        appr_unauth = ApplicationStateMachine.get_allowed_transitions(
            ApplicationStatus.APPROVED
        )
        self.assertNotIn("SUBMITTED", appr_unauth)
        self.assertIn("READY_FOR_REVIEW", appr_unauth)
        self.assertIn("WITHDRAWN", appr_unauth)

        # APPROVED with include_gate_protected=True includes SUBMITTED
        appr_auth = ApplicationStateMachine.get_allowed_transitions(
            ApplicationStatus.APPROVED, include_gate_protected=True
        )
        self.assertIn("SUBMITTED", appr_auth)

    def test_audit_event_types_for_all_valid_transitions(self):
        """All valid transitions produce meaningful, non-empty audit event type identifiers."""
        expected_events = {
            (ApplicationStatus.DRAFT, ApplicationStatus.PREPARING): "APPLICATION_PREPARATION_STARTED",
            (ApplicationStatus.PREPARING, ApplicationStatus.READY_FOR_REVIEW): "APPLICATION_READY_FOR_REVIEW",
            (ApplicationStatus.READY_FOR_REVIEW, ApplicationStatus.APPROVED): "PACKET_HUMAN_APPROVED",
            (ApplicationStatus.APPROVED, ApplicationStatus.SUBMITTED): "SUBMISSION_CONFIRMED",
            (ApplicationStatus.SUBMITTED, ApplicationStatus.IN_PROGRESS): "STATUS_CHANGED_TO_IN_PROGRESS",
            (ApplicationStatus.SUBMITTED, ApplicationStatus.ASSESSMENT): "ASSESSMENT_MILESTONE_LOGGED",
            (ApplicationStatus.SUBMITTED, ApplicationStatus.INTERVIEW): "INTERVIEW_MILESTONE_LOGGED",
            (ApplicationStatus.SUBMITTED, ApplicationStatus.REJECTED): "REJECTION_RECORDED",
            (ApplicationStatus.SUBMITTED, ApplicationStatus.WITHDRAWN): "APPLICATION_WITHDRAWN",
            (ApplicationStatus.IN_PROGRESS, ApplicationStatus.OFFER): "OFFER_RECEIVED",
            (ApplicationStatus.OFFER, ApplicationStatus.CLOSED): "APPLICATION_CLOSED",
            (ApplicationStatus.REJECTED, ApplicationStatus.IN_PROGRESS): "APPLICATION_REOPENED",
            (ApplicationStatus.WITHDRAWN, ApplicationStatus.IN_PROGRESS): "APPLICATION_REOPENED",
            (ApplicationStatus.CLOSED, ApplicationStatus.IN_PROGRESS): "APPLICATION_REOPENED",
        }
        for (src, dst), expected_evt in expected_events.items():
            evt = ApplicationStateMachine.get_transition_event_type(src, dst)
            self.assertEqual(evt, expected_evt, f"Mismatch for {src.value} -> {dst.value}")


if __name__ == "__main__":
    unittest.main()

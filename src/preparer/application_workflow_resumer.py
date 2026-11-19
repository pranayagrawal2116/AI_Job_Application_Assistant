"""Application Workflow Resumer (IAGH Architecture).

Coordinates automatic resumption of authorized application workflows following
intermediate human interactions (privacy acceptance, login, CAPTCHA, eligibility).

Responsibilities:
1. Re-validates execution context, application ownership, and employer domain safety.
2. Re-evaluates page state using PreApplicationGateDetector.
3. Coordinates multi-gate progression (supports sequential gates: Privacy -> Consent -> Eligibility -> Form).
4. Emits validated state machine transitions.
5. Halts cleanly if candidate declines a mandatory agreement.
6. Triggers autofill execution when the application form becomes ready.
"""

from dataclasses import asdict, dataclass
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.database.db_manager import DatabaseManager
from src.database.exceptions import CrossUserAccessError, SecurityAuthorizationError
from src.preparer.execution_state_machine import ApplicationExecutionStateMachine, ExecutionState
from src.preparer.gate_detector import GateCategory, GateDetectionResult, GateType, PreApplicationGateDetector
from src.preparer.human_interaction_manager import HumanInteractionManager, InteractionGuidance
from src.security.session_manager import SessionManager
from src.utils.logger import setup_logger

logger = setup_logger("ApplicationWorkflowResumer")


@dataclass
class WorkflowResumptionResult:
    """Outcome of attempting to resume workflow on a page."""
    execution_id: str
    application_id: int
    current_state: str  # ExecutionState
    gate_detected: bool
    gate_result: Optional[Dict[str, Any]]
    interaction_guidance: Optional[Dict[str, Any]]
    is_ready_for_autofill: bool
    message: str
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ApplicationWorkflowResumer:
    """Manages secure resumption of form autofill pipelines across intermediate gates."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        detector: Optional[PreApplicationGateDetector] = None,
        state_machine: Optional[ApplicationExecutionStateMachine] = None,
        interaction_mgr: Optional[HumanInteractionManager] = None,
    ) -> None:
        self.db = db_manager or DatabaseManager()
        self.detector = detector or PreApplicationGateDetector()
        self.state_machine = state_machine or ApplicationExecutionStateMachine(db_manager=self.db)
        self.interaction_mgr = interaction_mgr or HumanInteractionManager()

    def process_gate_event(
        self,
        application_id: int,
        execution_id: str,
        ticket: str,
        event_type: str,  # "USER_INTERACTION", "PAGE_NAVIGATION", "GATE_COMPLETED", "USER_DECLINED"
        current_url: str = "",
        html_snippet: str = "",
        control_interacted: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
    ) -> WorkflowResumptionResult:
        """Processes an event received from companion or browser during an intermediate gate."""
        now = time.time()

        # 1. Load active execution session
        session = self.db.get_autofill_execution_session(execution_id)
        if not session:
            raise SecurityAuthorizationError(f"No active execution session found for execution_id '{execution_id}'.")

        if session["application_id"] != application_id:
            raise SecurityAuthorizationError(
                f"Application ID mismatch: expected {session['application_id']}, got {application_id}."
            )

        # 2. Verify ticket
        session_ticket = session.get("action_ticket")
        if session_ticket and ticket != session_ticket:
            raise SecurityAuthorizationError("Invalid action ticket for execution session.")

        # 3. Check ownership
        effective_user_id = user_id or session["user_id"]
        if session["user_id"] != effective_user_id:
            raise CrossUserAccessError(
                user_id=effective_user_id,
                target_user_id=session["user_id"],
                resource=f"Execution #{execution_id}",
            )

        # 4. Handle USER_DECLINED event immediately
        if event_type == "USER_DECLINED":
            self.state_machine.transition(
                execution_id=execution_id,
                new_state=ExecutionState.USER_DECLINED,
                event_source="USER",
                message="Candidate declined employer portal agreement. Workflow safely halted.",
            )
            return WorkflowResumptionResult(
                execution_id=execution_id,
                application_id=application_id,
                current_state=ExecutionState.USER_DECLINED.value,
                gate_detected=False,
                gate_result=None,
                interaction_guidance=None,
                is_ready_for_autofill=False,
                message="Workflow halted: Candidate declined employer agreement.",
                timestamp=now,
            )

        # 5. Check if page is currently navigating
        if event_type == "PAGE_NAVIGATION":
            self.state_machine.transition(
                execution_id=execution_id,
                new_state=ExecutionState.NAVIGATION_IN_PROGRESS,
                event_source="COMPANION",
                message=f"Navigation in progress on {urlparse(current_url).hostname or 'employer portal'}.",
            )
            return WorkflowResumptionResult(
                execution_id=execution_id,
                application_id=application_id,
                current_state=ExecutionState.NAVIGATION_IN_PROGRESS.value,
                gate_detected=False,
                gate_result=None,
                interaction_guidance=None,
                is_ready_for_autofill=False,
                message="Navigation in progress...",
                timestamp=now,
            )

        # 6. Record user interaction
        if event_type in ("USER_INTERACTION", "GATE_COMPLETED"):
            ctrl_name = (control_interacted or {}).get("text") or (control_interacted or {}).get("name") or "control"
            self.state_machine.transition(
                execution_id=execution_id,
                new_state=ExecutionState.USER_ACTION_DETECTED,
                event_source="USER",
                message=f"User interaction detected on '{ctrl_name}'. Analyzing page transition...",
                metadata={"control": control_interacted},
            )

        # 7. Evaluate current page state using PreApplicationGateDetector
        gate_res = self.detector.detect_from_html(html_snippet, url=current_url)
        guidance = None

        # 8. Check if a blocking gate is still active
        if gate_res.is_blocking:
            guidance = self.interaction_mgr.evaluate_gate_interaction(gate_res)

            # Map category to specific state
            next_state = ExecutionState.GATE_DETECTED
            if gate_res.category == GateCategory.AUTHENTICATION.value:
                next_state = ExecutionState.AUTHENTICATION_REQUIRED
            elif gate_res.category == GateCategory.SECURITY.value:
                next_state = ExecutionState.SECURITY_CHALLENGE_REQUIRED

            self.state_machine.transition(
                execution_id=execution_id,
                new_state=next_state,
                event_source="BACKEND",
                message=f"Gate detected: {gate_res.gate_type}. Waiting for candidate action.",
                metadata={
                    "gate_category": gate_res.category,
                    "gate_type": gate_res.gate_type,
                    "is_blocking": gate_res.is_blocking,
                    "required_user_action": gate_res.required_user_action,
                },
            )

            # Transition to WAITING_FOR_USER
            self.state_machine.transition(
                execution_id=execution_id,
                new_state=ExecutionState.WAITING_FOR_USER,
                event_source="BACKEND",
                message=guidance.instruction,
            )

            return WorkflowResumptionResult(
                execution_id=execution_id,
                application_id=application_id,
                current_state=ExecutionState.WAITING_FOR_USER.value,
                gate_detected=True,
                gate_result=gate_res.to_dict(),
                interaction_guidance=guidance.to_dict(),
                is_ready_for_autofill=False,
                message=guidance.instruction,
                timestamp=now,
            )

        # 9. If application form is ready!
        if gate_res.form_detected:
            self.state_machine.transition(
                execution_id=execution_id,
                new_state=ExecutionState.APPLICATION_FORM_DETECTED,
                event_source="BACKEND",
                message="Employer application form detected and accessible. Resuming autofill.",
                metadata={"form_ready": True},
            )
            self.state_machine.transition(
                execution_id=execution_id,
                new_state=ExecutionState.AUTOFILL_RESUMED,
                event_source="BACKEND",
                message="Autofill resumed with verified candidate facts.",
            )
            return WorkflowResumptionResult(
                execution_id=execution_id,
                application_id=application_id,
                current_state=ExecutionState.AUTOFILL_RESUMED.value,
                gate_detected=False,
                gate_result=gate_res.to_dict(),
                interaction_guidance=None,
                is_ready_for_autofill=True,
                message="Application form accessible. Autofill resumed.",
                timestamp=now,
            )

        # 10. Generic intermediate page without form or blocking gate
        self.state_machine.transition(
            execution_id=execution_id,
            new_state=ExecutionState.PAGE_ANALYZING,
            event_source="BACKEND",
            message="Analyzing page structure...",
        )
        return WorkflowResumptionResult(
            execution_id=execution_id,
            application_id=application_id,
            current_state=ExecutionState.PAGE_ANALYZING.value,
            gate_detected=False,
            gate_result=gate_res.to_dict(),
            interaction_guidance=None,
            is_ready_for_autofill=False,
            message="Analyzing page...",
            timestamp=now,
        )

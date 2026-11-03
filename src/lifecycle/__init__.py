"""Application Lifecycle & State Machine Package (Phase 7.2).

Provides universal application state machine, transition validation, terminal state rules,
and audit event mapping.
"""

from src.lifecycle.state_machine import ApplicationStateMachine

__all__ = ["ApplicationStateMachine"]

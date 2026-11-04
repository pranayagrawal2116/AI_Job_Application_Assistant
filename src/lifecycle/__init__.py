"""Application Lifecycle & State Machine Package (Phase 7.2).

Provides universal application state machine, transition validation, terminal state rules,
and audit event mapping.
"""

from src.lifecycle.state_machine import ApplicationStateMachine
from src.lifecycle.follow_up_engine import (
    FollowUpRecommendation,
    FollowUpRecommendationEngine,
    FollowUpTemplate,
    FollowUpTemplateGenerator,
)

__all__ = [
    "ApplicationStateMachine",
    "FollowUpRecommendation",
    "FollowUpRecommendationEngine",
    "FollowUpTemplate",
    "FollowUpTemplateGenerator",
]

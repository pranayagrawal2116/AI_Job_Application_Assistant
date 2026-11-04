"""Authentication and server-side session validation helper for Streamlit views."""

from typing import Any, Optional, Tuple
import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from src.database.exceptions import SecurityAuthorizationError


def resolve_view_authenticated_user(
    view_name: str,
    custom_error_message: Optional[str] = None,
    st_module: Optional[Any] = None,
) -> Tuple[Optional[int], Optional[object]]:
    """Resolves and authoritatively validates the candidate's active server-side session.

    Fails closed if:
    - Session ID is missing or empty in Streamlit session_state.
    - Session does not exist, is expired, or is revoked in SessionManager.
    - client_user_id (if present in session_state) does not match the session's verified user_id.

    Returns:
        (user_id, verified_session) if successfully authenticated,
        or (None, None) if authentication fails (renders standard error/info message).
    """
    _st = st_module if st_module is not None else st
    session_id = _st.session_state.get("authenticated_session_id") or _st.session_state.get("session_id")
    raw_uid = _st.session_state.get("authenticated_user_id") or _st.session_state.get("user_id")

    err_msg = custom_error_message or f"🔒 Authentication required. Please sign in to access {view_name}."

    if not session_id or not isinstance(session_id, str) or not session_id.strip():
        _st.error(err_msg)
        _st.info(
            "Your session is missing, invalid, or expired.\n"
            "Please sign in with your candidate credentials to continue."
        )
        return None, None

    client_user_id: Optional[int] = None
    if raw_uid is not None:
        try:
            client_user_id = int(raw_uid)
        except (ValueError, TypeError):
            _st.error(err_msg)
            _st.info("Invalid user session format. Please sign in again.")
            return None, None

    service = DashboardService.get_instance()
    try:
        user_id, verified_sess = service.resolve_authenticated_candidate(
            session_id=session_id.strip(),
            client_user_id=client_user_id,
        )
        return user_id, verified_sess
    except SecurityAuthorizationError:
        _st.error(err_msg)
        _st.info(
            "Your session is missing, invalid, expired, or revoked.\n"
            "Please sign in again with your candidate credentials."
        )
        return None, None

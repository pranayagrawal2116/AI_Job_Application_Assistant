"""Candidate Application Tracker View (Phase 7.3.2.3).

Replaces legacy catalog-based tracker with the authentic multi-user candidate application tracker:
- Enforces session-derived candidate identity and multi-user isolation.
- Displays authoritative real-time lifecycle KPIs.
- Surfaces pending follow-up reminder alerts.
- Provides comprehensive List View and 5-Column Canonical Kanban Board.
- Enables deep application inspection: metadata, linked match evaluation, and read-only audit timeline.
- Supports historical prepared packet inspection and verified document downloads (PDF/DOCX).
- Secure employer portal navigation using validated canonical URLs.
- Anti-automation manual submission confirmation with cryptographic single-use action tickets.
- Lifecycle status transitions respecting authoritative state machine and mandatory terminal reopen rationale.
- Candidate-controlled reminder scheduling, completion, and deletion.
- Soft-archive management and candidate-scoped CSV data export.
"""

from __future__ import annotations

import streamlit as st

from dashboard.components.tracker_components import (
    render_application_card,
    render_follow_up_alert_bar,
    render_kanban_board_view,
    render_tracker_filter_toolbar,
    render_tracker_header,
    render_tracker_metrics_bar,
)
from dashboard.services.dashboard_service import DashboardService
from src.database.exceptions import (
    ApplicationNotFoundError,
    CrossUserAccessError,
    DatabaseError,
    SecurityAuthorizationError,
)


def render_application_tracker() -> None:
    """Renders the comprehensive Candidate Application Tracker interface."""
    # -------------------------------------------------------------------------
    # 1. AUTHENTICATED SESSION RESOLUTION & MULTI-USER ISOLATION
    # -------------------------------------------------------------------------
    session_id = st.session_state.get("authenticated_session_id") or st.session_state.get("session_id")
    client_user_id = st.session_state.get("authenticated_user_id") or st.session_state.get("user_id")

    if not session_id:
        st.error("Authentication required")
        st.info(
            "Your session is missing, invalid, or expired.\n"
            "Please sign in again to access your application tracker."
        )
        return

    service = DashboardService.get_instance()

    try:
        user_id, _ = service.resolve_authenticated_candidate(
            session_id=session_id,
            client_user_id=client_user_id,
        )
    except SecurityAuthorizationError:
        st.error("Authentication required")
        st.info(
            "Your session is missing, invalid, or expired.\n"
            "Please sign in again to access your application tracker."
        )
        return

    # -------------------------------------------------------------------------
    # 2. VIEW 1 — HEADER & AUTHORITATIVE KPI DASHBOARD
    # -------------------------------------------------------------------------
    render_tracker_header(user_id)

    # Read current include_archived setting from session state if already toggled
    include_archived = st.session_state.get(f"tracker_include_archived_{user_id}", False)

    try:
        metrics = service.get_candidate_tracker_metrics(
            session_id=session_id,
            include_archived=include_archived,
        )
    except (DatabaseError, SecurityAuthorizationError) as exc:
        st.error(f"Cannot load application tracker metrics: {exc}")
        return

    render_tracker_metrics_bar(metrics)
    st.divider()

    # -------------------------------------------------------------------------
    # 3. VIEW 2 — FOLLOW-UP ALERT BAR
    # -------------------------------------------------------------------------
    try:
        pending_follow_ups = service.list_application_follow_ups(
            session_id=session_id,
            is_completed=False,
            include_archived=False,
        )
    except (DatabaseError, SecurityAuthorizationError) as exc:
        st.error(f"Cannot load follow-up reminders: {exc}")
        pending_follow_ups = []

    # Preload user applications to map company/title in alerts
    try:
        raw_apps = service.list_candidate_applications(
            session_id=session_id,
            include_archived=True,
            limit=None,
        )
        app_map = {app.id: app for app in raw_apps if app.id is not None}
    except (DatabaseError, SecurityAuthorizationError):
        app_map = {}

    render_follow_up_alert_bar(service, session_id, user_id, pending_follow_ups, app_map)
    st.divider()

    # -------------------------------------------------------------------------
    # 4. VIEW 3 — FILTER TOOLBAR, SORTING & CSV EXPORT
    # -------------------------------------------------------------------------
    # Load candidate applications for CSV export
    try:
        export_apps = service.list_candidate_applications(
            session_id=session_id,
            include_archived=include_archived,
            limit=None,
        )
    except (DatabaseError, SecurityAuthorizationError):
        export_apps = []

    filters = render_tracker_filter_toolbar(user_id, export_apps)
    view_mode = filters["view_mode"]
    search_term = filters["search_term"]
    status_in = filters["status_in"]
    employment_type = filters["employment_type"]
    sort_by = filters["sort_by"]
    include_archived = filters["include_archived"]

    # -------------------------------------------------------------------------
    # 5. VIEW 4 & 5 — LIST VIEW / KANBAN BOARD
    # -------------------------------------------------------------------------
    raw_selected_app_id = st.session_state.get("tracker_selected_app_id")
    focused_app = None
    if raw_selected_app_id is not None:
        try:
            valid_id = int(raw_selected_app_id)
            if valid_id > 0:
                candidate_app = service.db.get_user_application(valid_id, user_id)
                if candidate_app and candidate_app.user_id == user_id:
                    focused_app = candidate_app
                else:
                    st.session_state.pop("tracker_selected_app_id", None)
            else:
                st.session_state.pop("tracker_selected_app_id", None)
        except (ApplicationNotFoundError, CrossUserAccessError, DatabaseError, ValueError, TypeError):
            st.session_state.pop("tracker_selected_app_id", None)
            focused_app = None

    if focused_app is not None:
        c_foc1, c_foc2 = st.columns([5, 1])
        with c_foc1:
            st.info(f"🎯 **Targeted Application Focus:** Showing Application #{focused_app.id} transferred from Application Preparer.")
        with c_foc2:
            if st.button("✕ Clear Focus", key=f"clear_foc_{user_id}"):
                st.session_state.pop("tracker_selected_app_id", None)
                st.rerun()

        render_application_card(
            focused_app,
            service,
            session_id,
            user_id,
            include_archived=bool(focused_app.is_archived),
            expanded=True,
        )
        st.divider()

    if view_mode == "List View":
        # Pagination Management
        page_key = f"tracker_page_{user_id}"
        filter_state_key = f"tracker_filter_state_{user_id}"
        current_filter_state = (search_term, tuple(status_in) if status_in else None, employment_type, sort_by, include_archived)

        # Reset pagination when filters change
        if st.session_state.get(filter_state_key) != current_filter_state:
            st.session_state[filter_state_key] = current_filter_state
            st.session_state[page_key] = 0

        page = st.session_state.get(page_key, 0)
        page_size = 20

        try:
            # Get total matching count
            matching_apps = service.list_candidate_applications(
                session_id=session_id,
                search_term=search_term,
                status_in=status_in,
                employment_type=employment_type,
                include_archived=include_archived,
                limit=None,
            )
            total_matching = len(matching_apps)

            # Get paginated slice
            apps = service.list_candidate_applications(
                session_id=session_id,
                search_term=search_term,
                sort_by=sort_by,
                limit=page_size,
                offset=page * page_size,
                include_archived=include_archived,
                status_in=status_in,
                employment_type=employment_type,
            )
        except (DatabaseError, SecurityAuthorizationError) as exc:
            st.error(f"Cannot load applications: {exc}")
            return

        if total_matching == 0:
            st.info("No applications match your filter criteria.")
            st.caption("Try adjusting your search terms or status filters, or start a new application in the Application Preparer.")
            return

        start_idx = page * page_size + 1
        end_idx = min((page + 1) * page_size, total_matching)
        st.markdown(f"**Showing {start_idx}–{end_idx} of {total_matching} Tracked Opportunities**")

        for app in apps:
            if focused_app is not None and app.id == focused_app.id:
                continue
            render_application_card(app, service, session_id, user_id, include_archived, expanded=False)

        # Pagination controls
        total_pages = max(1, (total_matching + page_size - 1) // page_size)
        if total_pages > 1:
            st.markdown("<br>", unsafe_allow_html=True)
            col_prev, col_ind, col_next = st.columns([1, 2, 1])
            with col_prev:
                if page > 0 and st.button("⬅️ Previous Page", key=f"prev_btn_{user_id}_{page}"):
                    st.session_state[page_key] = page - 1
                    st.rerun()
            with col_ind:
                st.markdown(f"<div style='text-align: center; padding-top: 6px;'>Page {page + 1} of {total_pages}</div>", unsafe_allow_html=True)
            with col_next:
                if (page + 1) < total_pages and st.button("Next Page ➡️", key=f"next_btn_{user_id}_{page}"):
                    st.session_state[page_key] = page + 1
                    st.rerun()

    else:
        # Kanban Board View
        try:
            kanban_apps = service.list_candidate_applications(
                session_id=session_id,
                search_term=search_term,
                sort_by=sort_by,
                limit=None,
                offset=0,
                include_archived=include_archived,
                status_in=status_in,
                employment_type=employment_type,
            )
        except (DatabaseError, SecurityAuthorizationError) as exc:
            st.error(f"Cannot load applications for Kanban Board: {exc}")
            return

        kanban_display_apps = [
            app for app in kanban_apps
            if not (focused_app is not None and app.id == focused_app.id)
        ]
        render_kanban_board_view(kanban_display_apps, service, session_id, user_id, include_archived, follow_ups=pending_follow_ups)

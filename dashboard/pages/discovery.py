"""Discovery Management Page: Orchestrate searches, monitor source health, and inspect anti-automation logs."""

from datetime import datetime
import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from src.scraper.discovery.source_registry import SourceRegistry


def render_discovery():
    """Renders discovery control center, live adapter telemetry, and restriction inspector."""
    st.markdown("## 🚀 Discovery Management")
    st.caption("Trigger multi-source internship discovery across India and Remote feeds with failure isolation.")

    service = DashboardService.get_instance()
    reg = SourceRegistry.create_default()

    # Session State for Discovery Status
    if "is_discovering" not in st.session_state:
        st.session_state["is_discovering"] = False
    if "last_summary" not in st.session_state:
        st.session_state["last_summary"] = None

    c_cfg, c_stat = st.columns([3, 2])

    with c_cfg:
        st.markdown("### ⚙️ Discovery Configuration")

        default_roles = [
            "Artificial Intelligence Intern",
            "Machine Learning Intern",
            "Data Science Intern",
            "Python Developer Intern",
            "Deep Learning Intern",
            "Generative AI Intern",
            "NLP Intern",
            "Computer Vision Intern",
        ]
        selected_roles = st.multiselect(
            "Target Internship Roles",
            options=default_roles,
            default=["Artificial Intelligence Intern", "Machine Learning Intern"],
        )

        default_locations = ["Remote", "Pune", "Bengaluru", "Mumbai", "Hyderabad", "India"]
        selected_locations = st.multiselect(
            "Target Locations",
            options=default_locations,
            default=["Remote", "Pune"],
        )

        col_q, col_lim = st.columns(2)
        with col_q:
            max_queries = st.slider("Max Search Queries", min_value=1, max_value=8, value=3)
        with col_lim:
            max_per_src = st.slider("Max Results Per Source", min_value=5, max_value=25, value=10)

        # Trigger button
        if st.session_state["is_discovering"]:
            st.warning("⏳ A discovery run is currently in progress. Please wait for it to complete.")
        else:
            if st.button("🚀 Start Live Discovery Run", type="primary", use_container_width=True):
                if not selected_roles or not selected_locations:
                    st.error("Please select at least one role and one location.")
                else:
                    st.session_state["is_discovering"] = True
                    with st.spinner("Executing discovery across all enabled adapters (Internshala, LinkedIn, ATS)..."):
                        try:
                            summary = service.run_discovery(
                                roles=selected_roles,
                                locations=selected_locations,
                                max_queries=max_queries,
                                max_results_per_source=max_per_src,
                            )
                            st.session_state["last_summary"] = summary
                            st.success(f"Discovery complete! Saved {summary.new_jobs_saved} new jobs ({summary.duplicates_skipped} duplicates skipped).")
                        except Exception as e:
                            st.error(f"Discovery error: {e}")
                        finally:
                            st.session_state["is_discovering"] = False
                            st.rerun()

    with c_stat:
        st.markdown("### 📡 Adapter Health & Operational Status")
        statuses = reg.get_source_statuses()
        for sid, sdata in statuses.items():
            name = sdata["name"]
            is_healthy = sdata["healthy"]
            health_badge = "🟢 Healthy" if is_healthy else "🟡 Degraded / Restricted"

            with st.container():
                st.markdown(
                    f"""
                    <div style="border: 1px solid #E2E8F0; border-radius: 6px; padding: 10px 14px; margin-bottom: 8px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong>{name}</strong>
                            <span style="font-size: 0.85rem; font-weight: 600;">{health_badge}</span>
                        </div>
                        <div style="font-size: 0.8rem; color: #64748B; margin-top: 4px;">
                            Requests: {sdata['total_requests']} &nbsp;|&nbsp; Success: {sdata['successful_requests']} &nbsp;|&nbsp; Restricted: {sdata['blocked_or_restricted']}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    st.divider()

    # Last Run Summary
    last_sum = st.session_state.get("last_summary")
    if last_sum:
        st.markdown("### 📋 Latest Discovery Run Results")
        r1, r2, r3, r4 = st.columns(4)
        with r1:
            st.metric("Total Payloads Discovered", last_sum.total_discovered)
        with r2:
            st.metric("New Jobs Persisted", last_sum.new_jobs_saved)
        with r3:
            st.metric("Duplicates Deduplicated", last_sum.duplicates_skipped)
        with r4:
            st.metric("Restricted Incidents", last_sum.restricted_incidents)

        if last_sum.restricted_notices:
            st.markdown("#### 🛡️ Logged Access Restrictions (Preserved for Human Review)")
            for notice in last_sum.restricted_notices:
                st.warning(f"**Platform:** {notice['platform']} | **Reason:** {notice['reason']} | **URL:** [{notice['url']}]({notice['url']})")

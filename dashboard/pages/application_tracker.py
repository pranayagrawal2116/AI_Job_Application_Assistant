"""Application Tracker Page: State machine management, audit logging, and human-in-the-loop verification."""

import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from src.database.models import ApplicationStatus


def render_application_tracker():
    """Renders the comprehensive application state machine tracker and audit log viewer."""
    st.markdown("## 📋 Application Tracker & State Machine")
    st.caption("Manage application lifecycles with strict human-in-the-loop verification and full audit trail.")

    service = DashboardService.get_instance()
    df = service.get_all_jobs_df()

    if df.empty:
        st.info("No applications to track. Run discovery to discover and evaluate opportunities.")
        return

    # Status summary metric chips
    st.markdown("#### Application Status Overview")
    statuses = [s.value for s in ApplicationStatus]
    status_counts = df["application_status"].value_counts().to_dict()

    cols = st.columns(len(statuses))
    for i, stat in enumerate(statuses):
        with cols[i]:
            cnt = status_counts.get(stat, 0)
            st.metric(label=stat, value=cnt)

    st.divider()

    # Filter by Status
    sel_status = st.selectbox(
        "Filter by Application Status",
        options=["All Statuses"] + statuses,
    )

    tracked_df = df if sel_status == "All Statuses" else df[df["application_status"] == sel_status]

    st.markdown(f"**Tracking {len(tracked_df)} Opportunities**")

    # Table of Applications
    for _, row in tracked_df.iterrows():
        job_id = row["id"]
        title = row["job_title"]
        company = row["company_name"]
        curr_stat = row["application_status"]
        score = row["match_score"]
        tier = row["match_classification"]
        notes = row.get("notes", "")

        with st.expander(f"[{curr_stat.upper()}] {title} at {company} (Score: {score:.1f})", expanded=False):
            col_info, col_form = st.columns([3, 2])

            with col_info:
                st.markdown(f"**Company:** {company}")
                st.markdown(f"**Location:** {row['location']} | **Mode:** {row['work_arrangement']}")
                st.markdown(f"**Platform:** {row['platform']} | **Match Tier:** {tier}")
                if row.get("job_url"):
                    st.link_button("🌐 Open Job Link", url=row["job_url"])

                # Audit logs for this job
                logs = service.db.get_application_logs(job_id)
                if logs:
                    st.markdown("**Recent Audit History:**")
                    for log in logs[-3:]:
                        st.caption(f"• `{log.timestamp}` — **{log.action}**: {log.details}")

            with col_form:
                st.markdown("#### Transition Status")
                next_stat = st.selectbox(
                    "New Status",
                    options=statuses,
                    index=statuses.index(curr_stat) if curr_stat in statuses else 0,
                    key=f"status_sel_{job_id}",
                )

                approver = ""
                if next_stat == ApplicationStatus.APPLIED.value:
                    st.warning("⚠️ **Safety Safeguard**: Human submission authorization is mandatory.")
                    approver = st.text_input(
                        "Authorized Human Approver Name",
                        placeholder="e.g. Candidate Pranay",
                        key=f"appr_{job_id}",
                    )

                notes_input = st.text_area(
                    "Application Notes",
                    value=notes,
                    height=70,
                    key=f"notes_{job_id}",
                )

                if st.button("Save Transition", key=f"trans_btn_{job_id}"):
                    succ, msg = service.update_application_status(
                        job_id=job_id,
                        new_status=next_stat,
                        notes=notes_input,
                        approver_name=approver if next_stat == ApplicationStatus.APPLIED.value else None,
                    )
                    if succ:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

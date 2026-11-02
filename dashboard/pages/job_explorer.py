"""Job Explorer Page: Search, filter, inspect, and manage discovered internships."""

import streamlit as st

from dashboard.components.filters import render_job_filters
from dashboard.components.job_card import render_job_card
from dashboard.components.score_breakdown import render_score_breakdown
from dashboard.services.dashboard_service import DashboardService


def render_job_explorer():
    """Renders the searchable, filterable job explorer with comprehensive detail inspector."""
    st.markdown("## 🔍 Explore Internship Opportunities")
    st.caption("Search, filter, and inspect verified AI/ML internships discovered from supported platforms.")

    service = DashboardService.get_instance()
    df = service.get_all_jobs_df()

    if df.empty:
        st.info("No job records available in the database. Use Discovery Management to search for internships.")
        return

    # Initialize detail selection state
    if "selected_job_id" not in st.session_state:
        st.session_state["selected_job_id"] = None

    # Render Filter Component
    filtered_df = render_job_filters(df)

    # Metrics summary of current filter
    st.markdown(
        f"**Showing {len(filtered_df)} of {len(df)} total opportunities** "
        f"({(filtered_df['is_eligible'] == True).sum()} Eligible)"
    )

    # View Mode Toggle & Sorting
    c_sort, c_view = st.columns([3, 1])
    with c_sort:
        sort_by = st.selectbox(
            "Sort Opportunities",
            options=["Highest Match Score", "Lowest Match Score", "Company Name (A-Z)", "Job Title (A-Z)"],
        )
        if sort_by == "Highest Match Score":
            filtered_df = filtered_df.sort_values(by="match_score", ascending=False)
        elif sort_by == "Lowest Match Score":
            filtered_df = filtered_df.sort_values(by="match_score", ascending=True)
        elif sort_by == "Company Name (A-Z)":
            filtered_df = filtered_df.sort_values(by="company_name", ascending=True)
        elif sort_by == "Job Title (A-Z)":
            filtered_df = filtered_df.sort_values(by="job_title", ascending=True)

    with c_view:
        view_mode = st.radio("Display Mode", options=["Card View", "Table View"], horizontal=True)

    # Selection Handler
    def on_select_detail(job_id: int):
        st.session_state["selected_job_id"] = job_id

    def on_toggle_shortlist(job_id: int):
        success, msg = service.toggle_shortlist(job_id)
        if success:
            st.toast(msg, icon="⭐")
            st.rerun()
        else:
            st.error(msg)

    # 1. Detail Inspector (If a job is selected)
    selected_id = st.session_state.get("selected_job_id")
    if selected_id:
        detail_data = service.get_job_detail(selected_id)
        if detail_data:
            job = detail_data["job"]
            app = detail_data["application"]
            eval_res = detail_data["evaluation"]

            with st.container():
                st.markdown("---")
                header_col1, header_col2 = st.columns([4, 1])
                with header_col1:
                    st.markdown(f"### 📋 {job.job_title} at {job.company_name}")
                    st.markdown(f"**Location:** {job.location} | **Stipend:** {job.stipend or 'Not Disclosed'} | **Duration:** {job.internship_duration or 'Unspecified'} | **Platform:** {job.platform}")
                with header_col2:
                    if st.button("✖ Close Inspector"):
                        st.session_state["selected_job_id"] = None
                        st.rerun()

                # Score Breakdown Component
                render_score_breakdown(
                    evaluation=eval_res,
                    job_score=job.match_score,
                    tier=job.match_classification,
                    is_eligible=job.is_eligible,
                )

                # Tabs for Description, Requirements, and Status
                tab_desc, tab_req, tab_actions = st.tabs(["📄 Job Description", "🎓 Requirements & Eligibility", "⚡ Application Status & Notes"])

                with tab_desc:
                    st.markdown(job.job_description or "No detailed description provided.")
                    if job.job_url:
                        st.link_button("🌐 Open Official Job Posting", url=job.job_url)

                with tab_req:
                    st.markdown("#### Educational & Candidate Criteria")
                    st.write(f"- **Degree / Target Program:** {job.eligibility_criteria.get('degree', 'Computer Science / AI / Data Science') if isinstance(job.eligibility_criteria, dict) else 'B.Tech / Engineering'}")
                    st.write(f"- **Graduation Year:** {job.eligibility_criteria.get('graduation_year', '2026 – 2028 acceptable') if isinstance(job.eligibility_criteria, dict) else 'Not explicitly constrained'}")
                    st.write(f"- **Work Mode:** {job.work_arrangement or 'Unspecified'}")
                    if job.required_skills:
                        st.markdown("**Skills Listed in Opportunity:**")
                        st.write(", ".join(job.required_skills) if isinstance(job.required_skills, list) else str(job.required_skills))

                with tab_actions:
                    c_act1, c_act2 = st.columns(2)
                    with c_act1:
                        st.markdown("#### Update Status")
                        statuses = [
                            "Discovered", "Under Review", "Shortlisted", "Application Prepared",
                            "Awaiting Approval", "Applied", "Interview", "Rejected", "Withdrawn"
                        ]
                        curr_status = app.status.value if app else "Discovered"
                        new_stat = st.selectbox("Current Status", options=statuses, index=statuses.index(curr_status) if curr_status in statuses else 0)

                        approver = ""
                        if new_stat == "Applied":
                            st.warning("⚠️ Human-in-the-Loop Safeguard: Enter your name to verify human approval.")
                            approver = st.text_input("Human Approver Name (Cannot be automated/bot)")

                        if st.button("Update Application Status", key="upd_stat_btn"):
                            succ, msg = service.update_application_status(
                                job_id=job.id,
                                new_status=new_stat,
                                approver_name=approver if new_stat == "Applied" else None,
                            )
                            if succ:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)

                    with c_act2:
                        st.markdown("#### Personal Notes")
                        curr_notes = app.notes if app and app.notes else ""
                        new_notes = st.text_area("Candidate Notes", value=curr_notes, height=120)
                        if st.button("Save Notes", key="save_notes_btn"):
                            succ, msg = service.update_job_notes(job.id, new_notes)
                            if succ:
                                st.success(msg)
                            else:
                                st.error(msg)

                st.markdown("---")

    # 2. Opportunities Display (Cards or Table)
    if view_mode == "Table View":
        display_cols = [
            "id", "job_title", "company_name", "location", "stipend",
            "match_score", "match_classification", "is_eligible", "platform", "application_status"
        ]
        st.dataframe(
            filtered_df[display_cols],
            use_container_width=True,
            column_config={
                "id": st.column_config.NumberColumn("ID", width="small"),
                "match_score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%.1f"),
                "is_eligible": st.column_config.CheckboxColumn("Eligible?"),
            },
            hide_index=True,
        )
    else:
        for _, row in filtered_df.iterrows():
            render_job_card(
                job_data=row.to_dict(),
                on_select_detail=on_select_detail,
                on_toggle_shortlist=on_toggle_shortlist,
                is_shortlist_view=False,
            )

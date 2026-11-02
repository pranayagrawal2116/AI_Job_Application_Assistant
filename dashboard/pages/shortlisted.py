"""Shortlisted Jobs Page: Manage, take notes, and export prioritized opportunities."""

from datetime import datetime
import streamlit as st

from dashboard.components.job_card import render_job_card
from dashboard.components.score_breakdown import render_score_breakdown
from dashboard.services.dashboard_service import DashboardService


def render_shortlisted():
    """Renders the shortlist management page."""
    st.markdown("## ⭐ Shortlisted Opportunities")
    st.caption("Review, annotate, and prepare applications for your selected top internship matches.")

    service = DashboardService.get_instance()
    df = service.get_all_jobs_df()

    if df.empty:
        st.info("No jobs discovered yet.")
        return

    shortlist_df = df[df["application_status"] == "Shortlisted"]

    c_metrics, c_export = st.columns([3, 1])
    with c_metrics:
        st.markdown(f"**Total Shortlisted:** {len(shortlist_df)} opportunities")
    with c_export:
        if not shortlist_df.empty:
            csv_data = shortlist_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Export Shortlist CSV",
                data=csv_data,
                file_name=f"shortlisted_internships_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
            )

    if shortlist_df.empty:
        st.info("Your shortlist is currently empty. Explore discovered opportunities and click '⭐ Shortlist' to add items here.")
        return

    # Detail inspector state
    if "shortlist_detail_id" not in st.session_state:
        st.session_state["shortlist_detail_id"] = None

    def on_select_detail(job_id: int):
        st.session_state["shortlist_detail_id"] = job_id

    def on_toggle_shortlist(job_id: int):
        succ, msg = service.toggle_shortlist(job_id)
        if succ:
            st.toast(msg, icon="⭐")
            st.rerun()

    # Detail view
    selected_id = st.session_state.get("shortlist_detail_id")
    if selected_id:
        detail = service.get_job_detail(selected_id)
        if detail:
            job = detail["job"]
            app = detail["application"]
            eval_res = detail["evaluation"]

            with st.container():
                st.markdown("---")
                h1, h2 = st.columns([4, 1])
                with h1:
                    st.markdown(f"### 📋 {job.job_title} at {job.company_name}")
                with h2:
                    if st.button("✖ Close Inspector", key="close_sh_det"):
                        st.session_state["shortlist_detail_id"] = None
                        st.rerun()

                render_score_breakdown(
                    evaluation=eval_res,
                    job_score=job.match_score,
                    tier=job.match_classification,
                    is_eligible=job.is_eligible,
                )

                st.markdown("#### Notes & Preparation Status")
                c_n1, c_n2 = st.columns(2)
                with c_n1:
                    notes = st.text_area("Your Notes for this opportunity", value=app.notes if app and app.notes else "", height=100)
                    if st.button("Save Notes", key="save_sh_notes"):
                        succ, msg = service.update_job_notes(job.id, notes)
                        if succ:
                            st.success(msg)
                        else:
                            st.error(msg)
                with c_n2:
                    st.write("**Next Action:** Transition to 'Application Prepared' once resume and cover letter are tailored.")
                    if st.button("Mark as Application Prepared", key="prep_btn"):
                        succ, msg = service.update_application_status(job.id, "Application Prepared", notes=notes)
                        if succ:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)
                st.markdown("---")

    # Render Shortlist Cards
    for _, row in shortlist_df.iterrows():
        render_job_card(
            job_data=row.to_dict(),
            on_select_detail=on_select_detail,
            on_toggle_shortlist=on_toggle_shortlist,
            is_shortlist_view=True,
        )

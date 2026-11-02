"""Reusable Job Card component for list and grid displays."""

from typing import Any, Callable, Dict, Optional
import streamlit as st


def render_job_card(
    job_data: Dict[str, Any],
    on_select_detail: Optional[Callable[[int], None]] = None,
    on_toggle_shortlist: Optional[Callable[[int], None]] = None,
    is_shortlist_view: bool = False,
):
    """Renders a structured job opportunity card with metadata badges and quick actions."""
    job_id = job_data["id"]
    title = job_data["job_title"]
    company = job_data["company_name"]
    location = job_data.get("location", "Unspecified")
    stipend = job_data.get("stipend", "Not Disclosed")
    score = float(job_data.get("match_score", 0.0))
    tier = job_data.get("match_classification", "Low")
    is_eligible = bool(job_data.get("is_eligible", True))
    platform = job_data.get("platform", "Direct")
    url = job_data.get("job_url", "#")
    status = job_data.get("application_status", "Discovered")

    tier_colors = {
        "Excellent": "#10B981",
        "Good": "#3B82F6",
        "Moderate": "#F59E0B",
        "Low": "#EF4444",
    }
    tier_color = tier_colors.get(tier, "#64748B")

    with st.container():
        st.markdown(
            f"""
            <div style="border: 1px solid #E2E8F0; border-radius: 8px; padding: 14px 18px; margin-bottom: 12px; background-color: white;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <div style="font-size: 1.15rem; font-weight: 700; color: #0F172A;">
                            {title}
                        </div>
                        <div style="font-size: 0.95rem; font-weight: 600; color: #475569; margin-top: 2px;">
                            🏢 {company} &nbsp;•&nbsp; 📍 {location} &nbsp;•&nbsp; 💰 {stipend}
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <span style="background-color: {tier_color}; color: white; padding: 4px 8px; border-radius: 6px; font-weight: 700; font-size: 0.85rem;">
                            {score:.1f} pts ({tier})
                        </span>
                        <div style="margin-top: 4px;">
                            <span style="font-size: 0.75rem; background: {'#DCFCE7' if is_eligible else '#FEE2E2'}; color: {'#166534' if is_eligible else '#991B1B'}; padding: 2px 6px; border-radius: 4px; font-weight: 600;">
                                {'ELIGIBLE' if is_eligible else 'INELIGIBLE'}
                            </span>
                            <span style="font-size: 0.75rem; background: #F1F5F9; color: #475569; padding: 2px 6px; border-radius: 4px; font-weight: 600;">
                                {platform}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Action Buttons
        col_btn1, col_btn2, col_btn3, _ = st.columns([2, 2, 2, 6])
        with col_btn1:
            if st.button("🔍 View Details", key=f"det_btn_{job_id}"):
                if on_select_detail:
                    on_select_detail(job_id)
        with col_btn2:
            shortlist_label = "❌ Remove Shortlist" if is_shortlist_view or status == "Shortlisted" else "⭐ Shortlist"
            if st.button(shortlist_label, key=f"sh_btn_{job_id}"):
                if on_toggle_shortlist:
                    on_toggle_shortlist(job_id)
        with col_btn3:
            if url and url != "#":
                st.link_button("🌐 Open URL", url=url)

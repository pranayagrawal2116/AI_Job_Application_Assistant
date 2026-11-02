"""AI Job Application Assistant - Streamlit Dashboard Entrypoint."""

from pathlib import Path
import sys
import streamlit as st

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from dashboard.pages.analytics import render_analytics
from dashboard.pages.application_tracker import render_application_tracker
from dashboard.pages.candidate_profile import render_candidate_profile
from dashboard.pages.discovery import render_discovery
from dashboard.pages.job_explorer import render_job_explorer
from dashboard.pages.overview import render_overview
from dashboard.pages.settings import render_settings
from dashboard.pages.shortlisted import render_shortlisted
from dashboard.services.dashboard_service import DashboardService
from src.config import config


def main():
    st.set_page_config(
        page_title="AI Job Application Assistant",
        page_icon="💼",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Custom Clean Professional Styling
    st.markdown(
        """
        <style>
            /* Base Clean Layout */
            .main .block-container {
                padding-top: 2rem;
                padding-bottom: 3rem;
                max-width: 1400px;
            }
            /* Headers */
            h1, h2, h3 {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                font-weight: 700;
                letter-spacing: -0.5px;
            }
            /* Card Containers */
            .css-1r6slb0, .css-12w0qpk {
                border-radius: 8px;
            }
            /* Sidebar Styling */
            section[data-testid="stSidebar"] {
                border-right: 1px solid #E2E8F0;
            }
            /* Buttons */
            .stButton > button {
                border-radius: 6px;
                font-weight: 600;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # Sidebar Candidate Information
    service = DashboardService.get_instance()
    metrics = service.get_metrics()
    cand = config.candidate_profile
    personal = cand.get("personal", {})
    edu = cand.get("education", [{}])[0]

    with st.sidebar:
        st.markdown("### 💼 Job Assistant")
        st.markdown(f"**Candidate:** {personal.get('full_name', 'Pranay')}")
        st.caption(f"{edu.get('degree', 'B.Tech')} ({edu.get('major', 'AI & DS')}) | Class of {edu.get('expected_graduation_year', '2028')}")
        st.caption(f"🏛️ {edu.get('institution', 'MIT World Peace University')} | CGPA: {edu.get('current_cgpa', '7.6')}")

        st.divider()

        # Mini KPI badges in sidebar
        st.markdown(
            f"""
            <div style="font-size:0.85rem; line-height: 1.8;">
                <div>💼 <strong>{metrics['total_discovered']}</strong> Discovered Opportunities</div>
                <div>✅ <strong>{metrics['eligible_count']}</strong> Eligible Positions</div>
                <div>⭐ <strong>{metrics['shortlisted_count']}</strong> Shortlisted Jobs</div>
                <div>📬 <strong>{metrics['applied_count']}</strong> Applied (Human Approved)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.divider()
        st.caption("AI Job Application Assistant v1.0.0 • Human-in-the-Loop Safe")

    # Define Navigation Structure using st.navigation
    pages = [
        st.Page(render_overview, title="Overview", icon="📊", url_path="overview", default=True),
        st.Page(render_job_explorer, title="Explore Jobs", icon="🔍", url_path="explore"),
        st.Page(render_shortlisted, title="Shortlisted Jobs", icon="⭐", url_path="shortlisted"),
        st.Page(render_application_tracker, title="Application Tracker", icon="📋", url_path="tracker"),
        st.Page(render_analytics, title="Job Matching Analytics", icon="📈", url_path="analytics"),
        st.Page(render_discovery, title="Discovery Management", icon="🚀", url_path="discovery"),
        st.Page(render_candidate_profile, title="Candidate Profile", icon="👤", url_path="profile"),
        st.Page(render_settings, title="Settings", icon="⚙️", url_path="settings"),
    ]

    nav = st.navigation(pages)
    nav.run()


if __name__ == "__main__":
    main()

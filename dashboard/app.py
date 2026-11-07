"""AI Job Application Assistant - Streamlit Dashboard Entrypoint."""

from pathlib import Path
import sys
import streamlit as st

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from dashboard.views.analytics import render_analytics
from dashboard.views.application_preparer import render_application_preparer
from dashboard.views.application_tracker import render_application_tracker
from dashboard.views.auth_view import render_auth
from dashboard.views.candidate_profile import render_candidate_profile
from dashboard.views.discovery import render_discovery
from dashboard.views.job_description_analyzer import render_job_description_analyzer
from dashboard.views.job_explorer import render_job_explorer
from dashboard.views.overview import render_overview
from dashboard.views.resume_match_analysis import render_resume_match_analysis
from dashboard.views.settings import render_settings
from dashboard.views.shortlisted import render_shortlisted
from dashboard.services.dashboard_service import DashboardService


def ensure_app_storage(service: DashboardService) -> None:
    """Initializes required application storage directories on startup."""
    try:
        if service.db.db_path != ":memory:":
            Path(service.db.db_path).parent.mkdir(parents=True, exist_ok=True)
        getattr(service.db, "backup_dir", Path("data/storage/backups")).mkdir(parents=True, exist_ok=True)
        getattr(service.db, "exports_dir", Path("data/exports")).mkdir(parents=True, exist_ok=True)
        Path(service.storage_base_dir).mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        service.logger.warning("Storage directory auto-initialization warning: %s", exc)


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
    ensure_app_storage(service)
    metrics = service.get_metrics()
    auth_uid = st.session_state.get("authenticated_user_id") or st.session_state.get("user_id")
    auth_sess_id = st.session_state.get("authenticated_session_id") or st.session_state.get("session_id")

    if auth_uid:
        db_prof = service.db.get_user_candidate_profile(int(auth_uid))
        cand = db_prof.get("profile_data", {}) if db_prof else {}
        user_row = service.db.get_user_by_id(int(auth_uid))
    else:
        cand = {}
        user_row = None

    personal = cand.get("personal", {})
    edu = cand.get("education", [{}])[0] if cand.get("education") else {}

    with st.sidebar:
        st.markdown("### 💼 Job Assistant")
        if auth_uid and user_row:
            cand_name = personal.get("full_name") or user_row.get("full_name") or f"User #{auth_uid}"
            st.markdown(f"**Candidate:** {cand_name}")
            st.caption(f"📧 {user_row.get('email')}")
            if st.button("🚪 Sign Out", key="sidebar_sign_out_btn"):
                if auth_sess_id:
                    try:
                        service.logout_candidate(str(auth_sess_id))
                    except Exception:
                        pass
                for k in [
                    "authenticated_user_id",
                    "user_id",
                    "authenticated_session_id",
                    "session_id",
                    "candidate_name",
                    "user_email",
                ]:
                    st.session_state.pop(k, None)
                st.rerun()
        else:
            st.markdown("**Candidate:** Guest User")
            st.caption("🔒 Sign in to access private profile and applications")

        if edu.get("institution") or edu.get("degree"):
            major_str = f"({edu.get('major')})" if edu.get("major") else ""
            grad_str = f"| Class of {edu.get('expected_graduation_year')}" if edu.get("expected_graduation_year") else ""
            st.caption(f"{edu.get('degree', '')} {major_str} {grad_str}".strip())
            cgpa_str = f"| CGPA: {edu.get('current_cgpa')}" if edu.get("current_cgpa") else ""
            st.caption(f"🏛️ {edu.get('institution', '')} {cgpa_str}".strip())

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
        st.Page(render_auth, title="Sign In / Register", icon="🔑", url_path="login"),
        st.Page(render_resume_match_analysis, title="Resume Match Analysis", icon="🎯", url_path="resume_matcher"),
        st.Page(render_job_description_analyzer, title="Job Analyzer & Ingestion", icon="📑", url_path="job_analyzer"),
        st.Page(render_job_explorer, title="Explore Jobs", icon="🔍", url_path="explore"),
        st.Page(render_shortlisted, title="Shortlisted Jobs", icon="⭐", url_path="shortlisted"),
        st.Page(render_application_preparer, title="Application Preparer", icon="✍️", url_path="preparer"),
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

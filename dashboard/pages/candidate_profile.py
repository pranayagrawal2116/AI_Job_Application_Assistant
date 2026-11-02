"""Candidate Profile Page: Edit personal criteria, education, technical skills, and projects with audit history."""

import json
import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from src.config import config


def render_candidate_profile():
    """Renders editable candidate profile with schema validation and version snapshots."""
    st.markdown("## 👤 Candidate Profile Management")
    st.caption("Maintain your verified academic qualifications, technical proficiencies, and targeted internship preferences.")

    service = DashboardService.get_instance()
    prof = config.candidate_profile

    # Load latest snapshot from database if available
    db_record = service.db.get_latest_candidate_profile()
    if db_record and db_record.profile_data:
        prof = db_record.profile_data

    personal = prof.get("personal", {})
    edu = prof.get("education", [{}])[0]
    tech = prof.get("technical_skills", {})
    interests = prof.get("technical_interests", [])
    projects = prof.get("projects", [])
    prefs = config.candidate_preferences

    tab_edit, tab_view, tab_history = st.tabs([
        "✏️ Edit Profile",
        "📄 Active Profile View",
        "📜 Profile Version History",
    ])

    with tab_edit:
        with st.form("profile_edit_form"):
            st.markdown("### 🎓 Academic Credentials")
            c_edu1, c_edu2 = st.columns(2)
            with c_edu1:
                inst_name = st.text_input("Institution", value=edu.get("institution", "MIT World Peace University"))
                deg_name = st.text_input("Degree Program", value=edu.get("degree", "B.Tech"))
                major_name = st.text_input("Major / Specialization", value=edu.get("major", "Computer Science Engineering – AI & Data Science"))
            with c_edu2:
                grad_year = st.number_input("Expected Graduation Year", min_value=2024, max_value=2032, value=int(edu.get("expected_graduation_year", 2028)))
                cgpa_val = st.number_input("Current Cumulative CGPA", min_value=0.0, max_value=10.0, value=float(edu.get("current_cgpa", 7.6)), step=0.01)
                exp_level = st.selectbox("Experience Level", options=["Student", "Fresher", "Entry Level"], index=0)

            st.divider()

            st.markdown("### 💻 Technical Skills & Proficiencies")
            c_sk1, c_sk2 = st.columns(2)
            with c_sk1:
                prog_langs = st.text_area(
                    "Programming Languages (comma separated)",
                    value=", ".join(tech.get("programming_languages", ["Python", "Dart", "C++", "SQL"])),
                )
                domains_txt = st.text_area(
                    "Core Domains (comma separated)",
                    value=", ".join(tech.get("domains", ["Machine Learning", "Artificial Intelligence", "Data Science"])),
                )
            with c_sk2:
                libs_txt = st.text_area(
                    "Libraries & Frameworks (comma separated)",
                    value=", ".join(tech.get("frameworks_and_libraries", ["Pandas", "NumPy", "Scikit-learn", "Flutter"])),
                )
                interests_txt = st.text_area(
                    "Technical Interests (comma separated)",
                    value=", ".join(interests if interests else ["Python", "Machine Learning", "Data preprocessing", "Data visualization", "Flutter"]),
                )

            st.divider()

            st.markdown("### 🎯 Target Roles & Locations")
            c_t1, c_t2 = st.columns(2)
            with c_t1:
                roles_txt = st.text_area(
                    "Target Roles (comma separated)",
                    value=", ".join(prefs.get("target_roles", [
                        "Artificial Intelligence Intern", "Machine Learning Intern", "Data Science Intern", "Python Developer Intern"
                    ])),
                )
            with c_t2:
                locs_txt = st.text_area(
                    "Preferred Locations (comma separated)",
                    value=", ".join(prefs.get("locations", ["Pune", "Remote", "Bengaluru", "Mumbai", "India"])),
                )

            submitted = st.form_submit_button("💾 Save Profile Changes & Record Version", type="primary")

            if submitted:
                # Build validated profile dictionary
                updated_profile = {
                    "personal": personal,
                    "education": [
                        {
                            "institution": inst_name.strip(),
                            "degree": deg_name.strip(),
                            "major": major_name.strip(),
                            "expected_graduation_year": int(grad_year),
                            "current_cgpa": float(cgpa_val),
                            "is_current": True,
                        }
                    ],
                    "experience_level": exp_level,
                    "technical_skills": {
                        "programming_languages": [s.strip() for s in prog_langs.split(",") if s.strip()],
                        "domains": [s.strip() for s in domains_txt.split(",") if s.strip()],
                        "frameworks_and_libraries": [s.strip() for s in libs_txt.split(",") if s.strip()],
                    },
                    "technical_interests": [s.strip() for s in interests_txt.split(",") if s.strip()],
                    "projects": projects,
                    "preferences": {
                        "target_roles": [s.strip() for s in roles_txt.split(",") if s.strip()],
                        "locations": [s.strip() for s in locs_txt.split(",") if s.strip()],
                    },
                }

                succ, msg = service.save_candidate_profile(updated_profile)
                if succ:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)

    with tab_view:
        st.markdown("### Active Candidate Profile Data")
        st.json(prof)

    with tab_history:
        st.markdown("### SQLite Profile Version Audit")
        rec = service.db.get_latest_candidate_profile()
        if rec:
            st.info(f"Latest Recorded Snapshot ID: **{rec.id}** | Updated At: **{rec.updated_at}**")
        else:
            st.caption("No historical database snapshots recorded yet.")

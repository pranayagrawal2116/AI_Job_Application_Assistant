"""Resume Match Analysis View for Streamlit Dashboard.

Universal explainable resume-to-job matching interface across Tech, Healthcare,
Finance, Law, Engineering, and Management with transparent 100-point dimensional scoring,
three-state eligibility analysis (ELIGIBLE / INELIGIBLE / UNKNOWN), and immutable audit history.
"""

from typing import Any, Dict, Optional
import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from src.matcher.scoring_profiles import SCORING_PROFILES


def render_resume_match_analysis():
    """Renders the Universal Multi-User Resume-to-Job Matching Engine."""
    st.markdown("## 🎯 Resume-to-Job Matching & Eligibility Engine")
    st.caption(
        "Evaluate candidate qualifications against any job description with explainable 100-point scoring, "
        "three-state eligibility analysis (ELIGIBLE / INELIGIBLE / UNKNOWN), customizable career-stage weighting profiles, "
        "and zero-hallucination evidence verification."
    )

    service = DashboardService.get_instance()
    from dashboard.views.auth_utils import resolve_view_authenticated_user
    user_id, _ = resolve_view_authenticated_user(
        view_name="Resume Match Analysis",
        custom_error_message="⚠️ Authentication required: You must be logged in to access Resume Match Analysis.",
        st_module=st,
    )
    if not user_id:
        return

    # 1. Fetch User Resumes and Job Descriptions
    resumes = service.get_user_resumes(user_id=user_id)
    job_descriptions = service.get_user_job_descriptions(user_id=user_id)

    if not resumes:
        st.warning("⚠️ No resumes found in your account. Please upload a resume first under **Candidate Profile**.")
        return

    if not job_descriptions:
        st.warning("⚠️ No saved job descriptions found. Please ingest a job description first under **Job Analyzer & Ingestion**.")
        return

    # Configuration Form
    with st.expander("⚙️ Configure Matching Evaluation", expanded=True):
        col1, col2 = st.columns(2)

        with col1:
            resume_options = {
                r["id"]: f"Resume #{r['id']}: {r['original_filename']} ({r.get('label', 'General')}) [v{r.get('active_version', 1)}]"
                for r in resumes
            }
            selected_resume_id = st.selectbox(
                "Select Candidate Resume",
                options=list(resume_options.keys()),
                format_func=lambda x: resume_options[x],
            )

        with col2:
            jd_options = {
                jd.id: f"Job #{jd.id}: {jd.job_title} @ {jd.company_name} ({jd.source_type.upper()})"
                for jd in job_descriptions
            }
            selected_jd_id = st.selectbox(
                "Select Target Job Opportunity",
                options=list(jd_options.keys()),
                format_func=lambda x: jd_options[x],
            )

        # Profile Recommendation
        rec_profile_id, rec_reason = service.recommend_scoring_profile(
            user_id=user_id,
            resume_id=selected_resume_id,
            job_description_id=selected_jd_id,
        )

        col_prof1, col_prof2 = st.columns([2, 1])
        with col_prof1:
            profile_choices = list(SCORING_PROFILES.keys())
            default_index = profile_choices.index(rec_profile_id) if rec_profile_id in profile_choices else 0
            selected_profile_id = st.selectbox(
                "Scoring Profile",
                options=profile_choices,
                index=default_index,
                format_func=lambda pid: f"{SCORING_PROFILES[pid].name} ({pid})" + (" [Recommended]" if pid == rec_profile_id else ""),
            )

        with col_prof2:
            st.markdown("**Recommendation:**")
            st.caption(f"💡 *{rec_reason}*")

        prof_conf = SCORING_PROFILES[selected_profile_id]
        st.info(f"**{prof_conf.name} Profile:** {prof_conf.description} (Weights: " + ", ".join([f"{k.capitalize()}: {v:.0f} pts" for k, v in prof_conf.weights.items() if v > 0]) + ")")

        col_btn, _ = st.columns([1, 3])
        with col_btn:
            run_btn = st.button("🚀 Run Match Evaluation", type="primary", use_container_width=True)

    # State management for current evaluation result
    if run_btn:
        with st.spinner("Analyzing competencies, qualifications, experience, and eligibility..."):
            try:
                eval_result = service.run_match_evaluation(
                    user_id=user_id,
                    resume_id=selected_resume_id,
                    job_description_id=selected_jd_id,
                    scoring_profile_id=selected_profile_id,
                )
                st.session_state["active_match_result"] = eval_result.to_dict()
                st.success("✅ Match evaluation completed and saved to immutable audit history!")
            except Exception as e:
                st.error(f"❌ Evaluation error: {e}")
                return

    # Check if we have an active or selected result to display
    active_result: Optional[Dict[str, Any]] = st.session_state.get("active_match_result")

    # If no active result yet, check for latest match
    if not active_result:
        latest = service.get_user_match_history(user_id=user_id, resume_id=selected_resume_id, job_description_id=selected_jd_id)
        if latest:
            active_result = latest[0].to_dict()
            if isinstance(active_result.get("details_json"), dict):
                active_result = active_result["details_json"]

    if not active_result:
        st.info("Select a resume and job description, then click **Run Match Evaluation** to view detailed compatibility analytics.")
        _render_history_table(service, user_id)
        return

    # =========================================================================
    # DISPLAY EVALUATION RESULTS
    # =========================================================================
    st.divider()
    _render_evaluation_dashboard(active_result)
    _render_history_table(service, user_id)


def _render_evaluation_dashboard(result: Dict[str, Any]):
    """Renders the comprehensive match analytics dashboard."""
    score = float(result.get("match_score", 0.0))
    classification = result.get("match_classification", "Moderate Match")
    eligibility = result.get("eligibility_status", "UNKNOWN")
    confidence = float(result.get("assessment_confidence", 1.0)) * 100.0

    # Top KPI Badges
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)

    with kpi1:
        st.metric("Total Match Score", f"{score:.1f} / 100", delta=classification)

    with kpi2:
        if eligibility == "ELIGIBLE":
            st.metric("Eligibility Status", "✅ ELIGIBLE")
        elif eligibility == "INELIGIBLE":
            st.metric("Eligibility Status", "❌ INELIGIBLE")
        else:
            st.metric("Eligibility Status", "⚠️ UNKNOWN")

    with kpi3:
        st.metric("Data Confidence", f"{confidence:.0f}%", help="Degree of verified candidate data backing this assessment.")

    with kpi4:
        st.metric("Profile Applied", result.get("scoring_profile", "general_baseline"))

    # Snapshot and provenance metadata
    meta_cols = st.columns(3)
    with meta_cols[0]:
        st.caption(f"📄 **Resume Hash:** `{str(result.get('resume_file_hash', 'N/A'))[:12]}...`")
    with meta_cols[1]:
        st.caption(f"📑 **JD Snapshot:** `{str(result.get('job_snapshot_hash', 'N/A'))[:12]}...`")
    with meta_cols[2]:
        st.caption(f"🕒 **Evaluated:** `{result.get('evaluated_at', 'Just now')[:19]}`")

    st.markdown("---")

    # Detailed Tabs
    tab_score, tab_skills, tab_quals, tab_elig, tab_recs = st.tabs([
        "📊 Score Breakdown",
        "🛠️ Skill Analysis",
        "🎓 Qualifications & Experience",
        "⚖️ Eligibility & Concerns",
        "💡 Recommendations",
    ])

    # -------------------------------------------------------------------------
    # TAB 1: SCORE BREAKDOWN
    # -------------------------------------------------------------------------
    with tab_score:
        st.markdown("### 📊 100-Point Dimensional Breakdown")
        breakdown = result.get("dimension_breakdown", {})

        for dim_key, dim_data in breakdown.items():
            col_l, col_bar, col_pts = st.columns([3, 5, 2])
            max_pts = float(dim_data.get("max_points", 0.0))
            earned_pts = float(dim_data.get("earned_points", 0.0))
            pct = (earned_pts / max_pts) if max_pts > 0 else 1.0
            label = dim_data.get("dimension_label", dim_key.replace("_", " ").title())

            with col_l:
                st.markdown(f"**{label}**")
                st.caption(dim_data.get("notes", ""))
            with col_bar:
                st.progress(min(1.0, max(0.0, pct)))
            with col_pts:
                st.markdown(f"**{earned_pts:.1f}** / {max_pts:.1f} pts")

        explanations = result.get("scoring_explanations", {})
        if explanations:
            with st.expander("🔍 Detailed Dimensional Notes"):
                for k, exp in explanations.items():
                    st.write(f"- {exp}")

    # -------------------------------------------------------------------------
    # TAB 2: SKILL ANALYSIS
    # -------------------------------------------------------------------------
    with tab_skills:
        st.markdown("### 🛠️ Competency & Skill Alignment")
        skills_assessment = result.get("skills_assessment", [])

        exact_matches = [sa for sa in skills_assessment if sa.get("classification") == "EXACT_MATCH"]
        related_matches = [sa for sa in skills_assessment if sa.get("classification") == "RELATED_MATCH"]
        partial_matches = [sa for sa in skills_assessment if sa.get("classification") == "PARTIAL_MATCH"]
        missing_skills = [sa for sa in skills_assessment if sa.get("classification") == "MISSING"]

        s_col1, s_col2, s_col3, s_col4 = st.columns(4)
        s_col1.metric("Exact Matches", len(exact_matches))
        s_col2.metric("Related Matches", len(related_matches))
        s_col3.metric("Partial Matches", len(partial_matches))
        s_col4.metric("Missing Skills", len(missing_skills))

        # Skill Categories
        if exact_matches:
            with st.expander(f"🟢 Exact Matches ({len(exact_matches)})", expanded=True):
                for em in exact_matches:
                    mand_badge = " *(Mandatory)*" if em.get("is_mandatory") else " *(Preferred)*"
                    st.markdown(f"- **{em['job_skill']}**{mand_badge}: {em.get('candidate_evidence', '')}")

        if related_matches:
            with st.expander(f"🟡 Related Domain Matches ({len(related_matches)})", expanded=True):
                for rm in related_matches:
                    mand_badge = " *(Mandatory)*" if rm.get("is_mandatory") else " *(Preferred)*"
                    st.markdown(f"- **{rm['job_skill']}**{mand_badge}: {rm.get('explanation', '')}")

        if partial_matches:
            with st.expander(f"🟠 Partial / Context Overlap ({len(partial_matches)})"):
                for pm in partial_matches:
                    mand_badge = " *(Mandatory)*" if pm.get("is_mandatory") else " *(Preferred)*"
                    st.markdown(f"- **{pm['job_skill']}**{mand_badge}: {pm.get('candidate_evidence', pm.get('explanation', ''))}")

        if missing_skills:
            with st.expander(f"🔴 Missing Skills ({len(missing_skills)})", expanded=True):
                for ms in missing_skills:
                    mand_badge = " *(Mandatory)*" if ms.get("is_mandatory") else " *(Preferred)*"
                    st.markdown(f"- **{ms['job_skill']}**{mand_badge}: {ms.get('explanation', 'No supporting evidence found.')}")

    # -------------------------------------------------------------------------
    # TAB 3: QUALIFICATIONS & EXPERIENCE
    # -------------------------------------------------------------------------
    with tab_quals:
        st.markdown("### 🎓 Education, Tenure & Licensing Analysis")

        q_col1, q_col2 = st.columns(2)
        with q_col1:
            st.markdown("#### 🏛️ Education & Degrees")
            edu = result.get("education_analysis", {})
            st.markdown(f"- **Highest Degree Found:** {edu.get('highest_candidate_degree', 'Not Documented')}")
            st.markdown(f"- **Degree Level Status:** `{edu.get('status', 'N/A')}`")
            st.markdown(f"- **Major / Discipline:** `{edu.get('major_match', 'N/A')}`")
            st.markdown(f"- **CGPA Cutoff Status:** `{edu.get('cgpa_status', 'N/A')}`")
            for n in edu.get("notes", []):
                st.caption(f"ℹ️ {n}")

            st.markdown("#### 📜 Statutory Licenses & Certifications")
            certs = result.get("certification_analysis", {})
            st.markdown(f"- **Statutory License Status:** `{certs.get('license_status', 'N/A')}`")
            if certs.get("certifications_matched"):
                st.markdown(f"- **Matched Certifications:** {', '.join(certs['certifications_matched'])}")
            if certs.get("certifications_missing"):
                st.markdown(f"- **Missing Certifications:** {', '.join(certs['certifications_missing'])}")
            for n in certs.get("notes", []):
                st.caption(f"ℹ️ {n}")

        with q_col2:
            st.markdown("#### 💼 Employment & Duration")
            exp = result.get("experience_analysis", {})
            dur_months = exp.get("total_experience_months")
            cand_yrs = exp.get("candidate_years")
            cand_yrs_str = f"{cand_yrs:.1f} years" if cand_yrs is not None else "Unknown"

            st.markdown(f"- **Documented Experience:** {cand_yrs_str} ({dur_months or 0} months)")
            st.markdown(f"- **Required Experience:** {exp.get('required_years') or 0.0:.1f} years")
            st.markdown(f"- **Tenure Status:** `{exp.get('status', 'N/A')}`")
            st.markdown(f"- **Dates Missing Flag:** `{exp.get('experience_dates_missing', False)}`")
            for n in exp.get("notes", []):
                st.caption(f"ℹ️ {n}")

    # -------------------------------------------------------------------------
    # TAB 4: ELIGIBILITY & CONCERNS
    # -------------------------------------------------------------------------
    with tab_elig:
        st.markdown("### ⚖️ Three-State Eligibility Analysis")

        if eligibility == "ELIGIBLE":
            st.success("✅ **ELIGIBLE:** All assessable mandatory requirements are supported by verified candidate qualifications.")
        elif eligibility == "INELIGIBLE":
            st.error("❌ **INELIGIBLE:** One or more explicit, non-negotiable mandatory employer requirements are demonstrably unmet.")
        else:
            st.warning("⚠️ **UNKNOWN:** Available candidate records or job specification details cannot conclusively confirm all mandatory requirements.")

        st.markdown("#### 📋 Specific Eligibility Reasons")
        for reason in result.get("eligibility_reasons", []):
            st.write(f"- {reason}")

        concerns = result.get("eligibility_concerns", [])
        if concerns:
            st.markdown("#### ⚠️ Potential Concerns & Gaps")
            for c in concerns:
                st.write(f"- {c}")

    # -------------------------------------------------------------------------
    # TAB 5: RECOMMENDATIONS
    # -------------------------------------------------------------------------
    with tab_recs:
        st.markdown("### 💡 Candidate Recommendations for Job Fit")
        st.caption("Ethical, practical suggestions to optimize application readiness without fabricating unverified credentials.")

        recs = result.get("recommendations", [])
        if recs:
            for i, r in enumerate(recs, 1):
                st.markdown(f"{i}. {r}")
        else:
            st.info("No immediate profile modifications or gaps flagged for this opportunity.")


def _render_history_table(service: DashboardService, user_id: int):
    """Renders historical match evaluation audit log."""
    st.markdown("---")
    st.markdown("### 📜 Match Evaluation History")

    history = service.get_user_match_history(user_id=user_id)
    if not history:
        st.caption("No historical evaluations recorded yet.")
        return

    hist_rows = []
    for h in history:
        hist_rows.append({
            "Match ID": h.id,
            "Resume #": h.resume_id,
            "Job #": h.job_description_id or h.job_id,
            "Score": f"{h.match_score:.1f}",
            "Classification": h.match_classification,
            "Eligibility": h.eligibility_status,
            "Profile": h.scoring_profile,
            "Evaluated At": str(h.evaluated_at)[:19] if h.evaluated_at else "",
        })

    st.dataframe(hist_rows, use_container_width=True)

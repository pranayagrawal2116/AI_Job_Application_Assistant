"""Candidate Profile & Resume Management View.

Supports multi-resume management, universal profile editing across all professions,
provenance tracking, diff-based synchronization, and immutable SQLite version snapshots.
"""

from datetime import datetime, timezone
import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from src.config import config
from src.preparer.profile_updater import ProfileUpdater
from src.preparer.resume_parser import ResumeParser, VerificationStatus


def get_current_user_id() -> int:
    """Returns the active user_id from session state or default."""
    return st.session_state.get("user_id", 1)


def render_candidate_profile():
    """Renders universal multi-resume management and candidate profile editor."""
    st.markdown("## 👤 Candidate Profile & Resume Management")
    st.caption(
        "Manage your resumes across roles and industries, inspect field provenance, "
        "and maintain your universal professional profile."
    )

    service = DashboardService.get_instance()
    user_id = get_current_user_id()

    # Load active profile from SQLite or config fallback
    db_record = service.db.get_user_candidate_profile(user_id)
    if db_record and db_record.get("profile_data"):
        prof = db_record["profile_data"]
    else:
        # Fallback to latest single-candidate snapshot or config
        legacy_rec = service.db.get_latest_candidate_profile()
        if legacy_rec and legacy_rec.profile_data:
            prof = legacy_rec.profile_data
        else:
            prof = config.candidate_profile

    tab_resumes, tab_edit, tab_sync, tab_history = st.tabs([
        "📁 Resumes & Documents",
        "✏️ Universal Profile Editor",
        "🔄 Resume-Profile Synchronization",
        "📜 Version History & Audit",
    ])

    # =========================================================================
    # TAB 1: RESUMES & DOCUMENTS
    # =========================================================================
    with tab_resumes:
        st.markdown("### 📤 Upload New Resume")
        st.caption("Upload your resume in PDF or DOCX format (max 10 MB). Each file is cryptographically validated and isolated.")

        with st.form("upload_resume_form", clear_on_submit=True):
            col_f1, col_f2 = st.columns([3, 2])
            with col_f1:
                uploaded_file = st.file_uploader(
                    "Choose Resume File",
                    type=["pdf", "docx"],
                    help="Upload a standard PDF or Word document.",
                )
            with col_f2:
                resume_label = st.text_input("Label / Description", value="General", help="e.g. AI/ML Focus, Management, Clinical")
                target_role = st.text_input("Target Role / Profession", placeholder="e.g. Data Scientist, Cardiologist, Attorney")
                is_primary_check = st.checkbox("Set as Primary Resume", value=False)

            upload_submit = st.form_submit_button("🚀 Upload & Parse Resume", type="primary")

            if upload_submit:
                if not uploaded_file:
                    st.error("Please select a file to upload.")
                else:
                    file_bytes = uploaded_file.read()
                    success, msg, rec = service.upload_user_resume(
                        user_id=user_id,
                        file_bytes=file_bytes,
                        original_filename=uploaded_file.name,
                        label=resume_label,
                        target_role=target_role or None,
                        set_as_primary=is_primary_check,
                    )
                    if success:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(f"Upload failed: {msg}")

        st.divider()
        st.markdown("### 📋 Your Uploaded Resumes")

        user_resumes = service.get_user_resumes(user_id)
        if not user_resumes:
            st.info("No resumes uploaded yet. Upload your first resume above to begin.")
        else:
            for res in user_resumes:
                res_id = res["id"]
                is_prim = bool(res.get("is_primary", 0))
                badge = " ⭐ **[PRIMARY RESUME]**" if is_prim else ""
                label_txt = res.get("label") or "General"
                role_txt = f" | Target: **{res.get('target_role')}**" if res.get("target_role") else ""

                with st.expander(f"📄 **{res['original_filename']}** — *{label_txt}*{role_txt}{badge}", expanded=is_prim):
                    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                    with col_m1:
                        st.metric("Format", res.get("file_format", "PDF").upper())
                    with col_m2:
                        size_kb = (res.get("file_size_bytes") or 0) / 1024
                        st.metric("Size", f"{size_kb:.1f} KB")
                    with col_m3:
                        st.metric("Version", f"v{res.get('active_version', 1)}")
                    with col_m4:
                        st.metric("Status", res.get("parsing_status", "COMPLETED"))

                    st.caption(f"Uploaded: {res.get('uploaded_at')} | Content SHA-256: `{res.get('file_hash', '')[:16]}...`")

                    # Actions row
                    c_act1, c_act2, c_act3 = st.columns([2, 2, 2])
                    with c_act1:
                        file_data, fname, mime = service.get_resume_download_data(user_id, res_id)
                        if file_data:
                            st.download_button(
                                label="⬇️ Download Original",
                                data=file_data,
                                file_name=res["original_filename"],
                                mime=mime,
                                key=f"dl_{res_id}",
                            )
                    with c_act2:
                        if not is_prim:
                            if st.button("⭐ Make Primary", key=f"prim_{res_id}"):
                                succ, p_msg = service.set_primary_resume(user_id, res_id)
                                if succ:
                                    st.success(p_msg)
                                    st.rerun()
                                else:
                                    st.error(p_msg)
                    with c_act3:
                        if st.button("🗑️ Delete Resume", key=f"del_{res_id}", type="secondary"):
                            succ, d_msg = service.delete_user_resume(user_id, res_id)
                            if succ:
                                st.success(d_msg)
                                st.rerun()
                            else:
                                st.error(d_msg)

                    # Version Upload Sub-section
                    with st.expander("🔄 Upload New Version for this Resume"):
                        with st.form(f"version_form_{res_id}"):
                            new_v_file = st.file_uploader("Select updated file", type=["pdf", "docx"], key=f"v_file_{res_id}")
                            change_notes = st.text_input("Change Notes / Summary", placeholder="e.g. Added AWS certification", key=f"notes_{res_id}")
                            v_sub = st.form_submit_button("Upload New Version")
                            if v_sub and new_v_file:
                                succ, v_msg, _ = service.add_resume_version(
                                    user_id=user_id,
                                    resume_id=res_id,
                                    file_bytes=new_v_file.read(),
                                    original_filename=new_v_file.name,
                                    change_notes=change_notes,
                                )
                                if succ:
                                    st.success(v_msg)
                                    st.rerun()
                                else:
                                    st.error(v_msg)

    # =========================================================================
    # TAB 2: UNIVERSAL PROFILE EDITOR
    # =========================================================================
    with tab_edit:
        st.markdown("### ✏️ Candidate Profile Editor")
        st.caption("Review and edit your canonical candidate profile. Works for all professions and experience levels.")

        personal = prof.get("personal", {})
        edu_entries = prof.get("education", [])
        exp_entries = prof.get("work_experience", [])
        tech_skills = prof.get("technical_skills", {})
        all_skills = tech_skills.get("all_skills", [])
        provenance = prof.get("field_provenance", {})

        with st.form("universal_profile_form"):
            # 1. Personal & Contact
            st.markdown("#### 1. Personal & Contact Details")
            p_col1, p_col2 = st.columns(2)
            with p_col1:
                name_val = st.text_input("Full Name", value=personal.get("full_name", ""))
                email_val = st.text_input("Email Address", value=personal.get("email", ""))
                phone_val = st.text_input("Phone Number", value=personal.get("phone", ""))
                loc_val = st.text_input("Current Location", value=personal.get("location", ""))
            with p_col2:
                headline_val = st.text_input("Professional Headline", value=personal.get("headline", ""))
                github_val = st.text_input("GitHub URL", value=personal.get("github", ""))
                linkedin_val = st.text_input("LinkedIn URL", value=personal.get("linkedin", ""))
                portfolio_val = st.text_input("Portfolio / Website URL", value=personal.get("portfolio", ""))

            summary_val = st.text_area("Professional Summary / About Me", value=personal.get("summary", ""), height=100)

            st.divider()

            # 2. Education
            st.markdown("#### 2. Education & Credentials")
            edu_primary = edu_entries[0] if edu_entries else {}
            e_col1, e_col2 = st.columns(2)
            with e_col1:
                inst_val = st.text_input("Primary Institution / University", value=edu_primary.get("institution", ""))
                deg_val = st.text_input("Degree / Qualification", value=edu_primary.get("degree", ""))
                major_val = st.text_input("Major / Specialization", value=edu_primary.get("major", ""))
            with e_col2:
                grad_year_val = st.number_input(
                    "Graduation Year",
                    min_value=1970,
                    max_value=2035,
                    value=int(edu_primary.get("expected_graduation_year") or 2028),
                )
                cgpa_val = st.number_input(
                    "CGPA / GPA / Score",
                    min_value=0.0,
                    max_value=100.0,
                    value=float(edu_primary.get("current_cgpa") or 7.6),
                    step=0.01,
                )

            st.divider()

            # 3. Work Experience
            st.markdown("#### 3. Professional Experience")
            exp_primary = exp_entries[0] if exp_entries else {}
            w_col1, w_col2 = st.columns(2)
            with w_col1:
                emp_val = st.text_input("Recent Employer / Organization", value=exp_primary.get("employer", ""))
                title_val = st.text_input("Job Title / Role", value=exp_primary.get("job_title", ""))
            with w_col2:
                dur_val = st.text_input("Duration", value=exp_primary.get("duration", ""))

            resps_raw = exp_primary.get("responsibilities", [])
            resps_txt = "\n".join(resps_raw) if isinstance(resps_raw, list) else str(resps_raw)
            resps_val = st.text_area("Key Responsibilities & Outcomes (one per line)", value=resps_txt, height=120)

            st.divider()

            # 4. Skills & Competencies
            st.markdown("#### 4. Skills & Competencies")
            skills_txt = st.text_area(
                "All Professional Skills (comma separated)",
                value=", ".join(all_skills),
                height=100,
            )

            st.divider()

            # Submit and save
            save_btn = st.form_submit_button("💾 Save Profile Changes & Record Snapshot", type="primary")

            if save_btn:
                # Update provenance for modified fields as USER_CONFIRMED or USER_CORRECTED
                new_prov = dict(provenance)
                new_prov["full_name"] = {
                    "value": name_val.strip(),
                    "source_section": "Manual Profile Form",
                    "confidence": 1.0,
                    "verification_status": VerificationStatus.USER_CONFIRMED.value,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                new_prov["email"] = {
                    "value": email_val.strip(),
                    "source_section": "Manual Profile Form",
                    "confidence": 1.0,
                    "verification_status": VerificationStatus.USER_CONFIRMED.value,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }

                parsed_skills = [s.strip() for s in skills_txt.split(",") if s.strip()]
                parsed_resps = [r.strip() for r in resps_val.split("\n") if r.strip()]

                updated_data = dict(prof)
                updated_data["personal"] = {
                    "full_name": name_val.strip(),
                    "email": email_val.strip(),
                    "phone": phone_val.strip(),
                    "location": loc_val.strip(),
                    "headline": headline_val.strip(),
                    "github": github_val.strip(),
                    "linkedin": linkedin_val.strip(),
                    "portfolio": portfolio_val.strip(),
                    "summary": summary_val.strip(),
                }
                updated_data["education"] = [
                    {
                        "institution": inst_val.strip(),
                        "degree": deg_val.strip(),
                        "major": major_val.strip(),
                        "expected_graduation_year": int(grad_year_val),
                        "current_cgpa": float(cgpa_val),
                    }
                ]
                updated_data["work_experience"] = [
                    {
                        "employer": emp_val.strip(),
                        "job_title": title_val.strip(),
                        "duration": dur_val.strip(),
                        "responsibilities": parsed_resps,
                    }
                ]
                updated_data["technical_skills"] = {
                    "all_skills": parsed_skills,
                    "programming_languages": [s for s in parsed_skills if s in ["Python", "Dart", "C++", "Java", "JavaScript", "SQL"]],
                }
                updated_data["field_provenance"] = new_prov

                succ, msg = service.save_candidate_profile(updated_data)
                try:
                    service.db.save_user_candidate_profile(user_id, updated_data)
                except Exception:
                    pass

                if succ:
                    st.success("Candidate profile updated and recorded in SQLite!")
                    st.rerun()
                else:
                    st.error(msg)

    # =========================================================================
    # TAB 3: RESUME-PROFILE SYNCHRONIZATION
    # =========================================================================
    with tab_sync:
        st.markdown("### 🔄 Sync Profile From Uploaded Resume")
        st.caption(
            "Inspect what would change before updating. Fields you previously confirmed or corrected "
            "are protected and will never be overwritten without explicit approval."
        )

        user_resumes = service.get_user_resumes(user_id)
        if not user_resumes:
            st.info("No uploaded resumes available to sync from. Upload a resume in the 'Resumes & Documents' tab first.")
        else:
            options = {r["id"]: f"{r['original_filename']} ({r.get('label', 'General')}) v{r.get('active_version', 1)}" for r in user_resumes}
            selected_id = st.selectbox("Select Resume to Synchronize From", options=list(options.keys()), format_func=lambda x: options[x])

            if selected_id:
                try:
                    resume_path = service.db.get_resume_file_path(user_id, selected_id)
                    parser = ResumeParser()
                    parsed = parser.parse_file(resume_path)
                    updater = ProfileUpdater(db_manager=service.db)
                    diff = updater.diff_profile_with_resume(prof, parsed)

                    st.markdown("#### 📊 Synchronization Diff Analysis")

                    c_d1, c_d2, c_d3, c_d4 = st.columns(4)
                    with c_d1:
                        st.metric("🟢 New Fields", len(diff["new_fields"]))
                    with c_d2:
                        st.metric("🟡 Modified Fields", len(diff["modified_fields"]))
                    with c_d3:
                        st.metric("🔒 Protected Fields", len(diff["protected_fields"]))
                    with c_d4:
                        st.metric("⚪ Unchanged Fields", len(diff["unmodified_fields"]))

                    if diff["protected_fields"]:
                        st.warning("🔒 **Protected Fields Found:** The following fields were previously confirmed or corrected by you. They will NOT be overwritten unless you check 'Override Protected Fields'.")
                        for p_field in diff["protected_fields"]:
                            st.write(f"- **{p_field['field']}**: Current = `{p_field['current_value']}` vs Resume = `{p_field['new_value']}`")

                    if diff["new_fields"]:
                        st.info("🟢 **New Fields to Add:**")
                        for n_field in diff["new_fields"]:
                            st.write(f"- **{n_field['field']}**: `{n_field['new_value']}`")

                    if diff["modified_fields"]:
                        st.write("🟡 **Modified Fields:**")
                        for m_field in diff["modified_fields"]:
                            st.write(f"- **{m_field['field']}**: `{m_field['current_value']}` → `{m_field['new_value']}`")

                    with st.form("apply_sync_form"):
                        override_check = st.checkbox("Override Protected Fields (Proceed with caution)", value=False)
                        sync_submit = st.form_submit_button("⚡ Apply Approved Synchronization", type="primary")

                        if sync_submit:
                            synced_profile = updater.apply_approved_sync(
                                current_profile=prof,
                                resume=parsed,
                                approved_fields=None,
                                override_protected=override_check,
                            )
                            service.save_candidate_profile(synced_profile)
                            try:
                                service.db.save_user_candidate_profile(user_id, synced_profile)
                            except Exception:
                                pass
                            st.success("Successfully synchronized candidate profile from resume!")
                            st.rerun()

                except Exception as e:
                    st.error(f"Failed to inspect resume: {e}")

    # =========================================================================
    # TAB 4: VERSION HISTORY & AUDIT
    # =========================================================================
    with tab_history:
        st.markdown("### 📜 SQLite Profile Version History")
        st.caption("Immutable snapshots stored on every profile update or resume synchronization.")

        history = service.db.get_user_candidate_profile_history(user_id)
        if not history:
            # Check legacy snapshots
            rec = service.db.get_latest_candidate_profile()
            if rec:
                st.info(f"Active Snapshot ID: **#{rec.id}** | Updated At: **{rec.last_updated}**")
                st.json(rec.profile_data)
            else:
                st.caption("No historical profile snapshots recorded yet.")
        else:
            for snap in history:
                is_act = bool(snap.get("is_active", 0))
                act_badge = " [ACTIVE]" if is_act else ""
                v_num = snap.get("version", 1)
                with st.expander(f"Snapshot v{v_num} — {snap.get('last_updated')}{act_badge}", expanded=is_act):
                    st.caption(f"Profile Hash (SHA-256): `{snap.get('profile_hash', 'N/A')}`")
                    st.json(snap.get("profile_data", {}))

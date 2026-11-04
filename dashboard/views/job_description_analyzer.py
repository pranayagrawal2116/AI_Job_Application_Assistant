"""Job Description Analyzer & Ingestion View for Streamlit Dashboard.

Universal multi-user job ingestion interface supporting:
1. Pasted text ingestion with formatting preservation.
2. PDF and DOCX document uploads with strict security and size controls.
3. Safe public URL fetching with SSRF protection and anti-bot restriction detection.
4. Structured review, field provenance inspection, candidate corrections, and versioned snapshots.
"""

import json
import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from dashboard.views.auth_utils import resolve_view_authenticated_user
from src.database.exceptions import (
    UnsafeURLError,
    URLFetchRestrictedError,
)


def render_job_description_analyzer():
    """Renders the Universal Multi-User Job Description Ingestion and Analysis Interface."""
    st.markdown("## 📑 Job Description Analyzer & Ingestion Engine")
    st.caption(
        "Ingest, parse, and analyze job opportunities across any industry (Tech, Healthcare, Law, Finance, Engineering, etc.) "
        "with strict SSRF defense, document safety, zero-hallucination provenance, and immutable snapshot versioning."
    )

    user_id, _ = resolve_view_authenticated_user(
        view_name="Job Description Analyzer & Ingestion Engine",
        custom_error_message="🔒 Authentication required. Please sign in to analyze and ingest job descriptions.",
        st_module=st,
    )
    if not user_id:
        return

    service = DashboardService.get_instance()

    tab_paste, tab_upload, tab_url, tab_library = st.tabs([
        "📝 Paste Description Text",
        "📤 Upload Document (PDF / DOCX)",
        "🌐 Ingest from Job URL",
        "📚 Saved Opportunities Library",
    ])

    # =========================================================================
    # TAB 1: PASTE DESCRIPTION TEXT
    # =========================================================================
    with tab_paste:
        st.markdown("### 📝 Paste Job Opportunity Details")
        st.caption("Paste the full job listing text. Bullets, Unicode, formatting, and requirements are preserved.")

        col1, col2 = st.columns([2, 1])
        with col1:
            raw_text_input = st.text_area(
                "Job Listing Text",
                placeholder="Paste the complete job description, requirements, responsibilities, and qualifications here...",
                height=320,
                key="jd_paste_text_area",
            )
        with col2:
            st.markdown("##### 💡 Optional Metadata Hints")
            hint_title = st.text_input("Position Title (Optional)", placeholder="e.g. Senior Machine Learning Engineer", key="jd_paste_title")
            hint_company = st.text_input("Company / Organization (Optional)", placeholder="e.g. HealthTech Innovations", key="jd_paste_company")
            hint_location = st.text_input("Location / Mode (Optional)", placeholder="e.g. Bengaluru, India (Hybrid)", key="jd_paste_location")

            st.caption("Hints assist when the raw text lacks explicit headers.")

        if st.button("⚡ Analyze & Save Opportunity", type="primary", key="btn_ingest_pasted"):
            if not raw_text_input or len(raw_text_input.strip()) < 20:
                st.error("Please enter a job description of at least 20 characters.")
            else:
                with st.spinner("Analyzing cross-industry requirements and saving snapshot..."):
                    success, msg, jd = service.ingest_job_text(
                        user_id=user_id,
                        raw_text=raw_text_input,
                        hint_title=hint_title.strip() if hint_title else None,
                        hint_company=hint_company.strip() if hint_company else None,
                        hint_location=hint_location.strip() if hint_location else None,
                    )
                    if success and jd:
                        st.success(msg)
                        st.session_state["selected_jd_id"] = jd.id
                        st.rerun()
                    else:
                        st.error(msg)

    # =========================================================================
    # TAB 2: UPLOAD DOCUMENT (PDF / DOCX)
    # =========================================================================
    with tab_upload:
        st.markdown("### 📤 Upload Job Specification Document")
        st.caption("Upload official JD documents in PDF or DOCX format. Files are validated for magic bytes, max 10 MB, and stored in isolated user directories.")

        uploaded_file = st.file_uploader(
            "Select PDF or DOCX File",
            type=["pdf", "docx"],
            accept_multiple_files=False,
            key="jd_file_uploader",
        )

        if uploaded_file is not None:
            file_bytes = uploaded_file.getvalue()
            file_name = uploaded_file.name
            size_kb = len(file_bytes) / 1024

            col_u1, col_u2 = st.columns([2, 1])
            with col_u1:
                st.info(f"📄 **Selected File:** `{file_name}` ({size_kb:.1f} KB)")
            with col_u2:
                if st.button("🚀 Process & Ingest Document", type="primary", key="btn_process_uploaded_jd"):
                    with st.spinner("Validating file safety, extracting text, and parsing structured fields..."):
                        success, msg, jd = service.ingest_job_file(
                            user_id=user_id,
                            file_bytes=file_bytes,
                            original_filename=file_name,
                        )
                        if success and jd:
                            st.success(msg)
                            st.session_state["selected_jd_id"] = jd.id
                            st.rerun()
                        else:
                            st.error(msg)

    # =========================================================================
    # TAB 3: INGEST FROM PUBLIC JOB URL
    # =========================================================================
    with tab_url:
        st.markdown("### 🌐 Ingest from Public Job Listing URL")
        st.caption(
            "Safely fetches public postings with SSRF boundary defenses, redirect validation, and automated restriction detection. "
            "If the employer uses bot detection or login walls, you will be prompted to paste the text directly."
        )

        target_url = st.text_input(
            "Public Job Listing URL",
            placeholder="https://careers.company.com/jobs/12345 or https://jobs.lever.co/example/...",
            key="jd_target_url_input",
        )

        if st.button("🔍 Fetch, Validate & Parse", type="primary", key="btn_fetch_job_url"):
            if not target_url or not target_url.strip():
                st.error("Please enter a job URL.")
            else:
                with st.spinner("Validating network safety, verifying SSRF boundary, and fetching content..."):
                    try:
                        success, msg, jd, fetched = service.ingest_job_url(
                            user_id=user_id,
                            target_url=target_url.strip(),
                        )
                        if success and jd:
                            st.success(msg)
                            st.session_state["selected_jd_id"] = jd.id
                            st.rerun()
                        else:
                            st.error(msg)
                    except URLFetchRestrictedError as e:
                        st.warning(f"⚠️ Access Restricted: {e}")
                        st.markdown(
                            """
                            **Suggested Action:** The website prevents automated scrapers or requires a session login.
                            Please open the URL in your browser, copy the job description, and use the **📝 Paste Description Text** tab.
                            """
                        )
                    except UnsafeURLError as e:
                        st.error(f"🚫 Security Violation: {e}")
                    except Exception as e:
                        st.error(f"Error fetching job URL: {e}")

    # =========================================================================
    # TAB 4: SAVED OPPORTUNITIES LIBRARY & SNAPSHOT REVIEW
    # =========================================================================
    with tab_library:
        st.markdown("### 📚 Saved Opportunities & Immutable Snapshot Lineage")
        st.caption("Review extracted requirements, inspect field provenance, and perform candidate corrections.")

        include_superseded = st.checkbox("Show superseded revision snapshots", value=False, key="chk_include_superseded")
        saved_jds = service.get_user_job_descriptions(user_id=user_id, include_superseded=include_superseded)

        if not saved_jds:
            st.info("No saved job descriptions found. Use the tabs above to ingest your first opportunity.")
            return

        options = {f"#{jd.id}: {jd.job_title} @ {jd.company_name} ({jd.source_type.upper()})": jd.id for jd in saved_jds}
        selected_label = st.selectbox(
            "Select Opportunity to Inspect / Edit",
            options=list(options.keys()),
            key="sb_select_jd_to_view",
        )
        selected_id = options[selected_label]
        selected_jd = next((j for j in saved_jds if j.id == selected_id), saved_jds[0])

        parsed_data = {}
        if selected_jd.parsed_data:
            try:
                parsed_data = json.loads(selected_jd.parsed_data) if isinstance(selected_jd.parsed_data, str) else selected_jd.parsed_data
            except Exception:
                pass

        # Top summary cards
        c_meta1, c_meta2, c_meta3, c_meta4 = st.columns(4)
        with c_meta1:
            st.metric("Snapshot ID", f"#{selected_jd.id}")
            st.caption(f"Status: {'Active' if selected_jd.is_active else 'Superseded'}")
        with c_meta2:
            conf_val = selected_jd.extraction_confidence or 1.0
            st.metric("Extraction Confidence", f"{int(conf_val * 100)}%")
        with c_meta3:
            st.metric("Ingestion Source", selected_jd.source_type.upper())
            if selected_jd.source_url:
                st.caption(f"[Original Link]({selected_jd.source_url})")
            elif selected_jd.original_filename:
                st.caption(f"File: `{selected_jd.original_filename}`")
        with c_meta4:
            st.metric("Parser Version", selected_jd.parser_version or "1.0.0")
            st.caption(f"Saved: {selected_jd.created_at[:16] if selected_jd.created_at else ''}")

        st.divider()

        # Detailed view and editing tabs
        sub_tab_view, sub_tab_edit, sub_tab_lineage = st.tabs([
            "🔍 Structured Requirements",
            "✏️ Candidate Review & Correction",
            "📜 Snapshot Version History",
        ])

        with sub_tab_view:
            col_v1, col_v2 = st.columns(2)

            with col_v1:
                st.markdown("#### 🎯 Core Requirements")
                st.markdown(f"**Job Title:** {selected_jd.job_title}")
                st.markdown(f"**Company:** {selected_jd.company_name}")
                st.markdown(f"**Location:** {parsed_data.get('location') or 'Not Specified'}")
                st.markdown(f"**Work Arrangement:** {parsed_data.get('work_arrangement') or 'Undisclosed'}")
                st.markdown(f"**Employment Type:** {parsed_data.get('employment_type') or 'Full-time'}")

                min_exp = parsed_data.get("min_years_experience")
                st.markdown(f"**Required Experience:** {f'{min_exp}+ years' if min_exp is not None else 'Not Specified'}")

                st.markdown("##### 📌 Mandatory Skills (Must Have)")
                mand_skills = parsed_data.get("mandatory_skills", [])
                if mand_skills:
                    st.write(", ".join([f"`{s}`" for s in mand_skills]))
                else:
                    st.caption("No specific mandatory skills isolated.")

                st.markdown("##### ⭐ Preferred Skills (Nice to Have)")
                pref_skills = parsed_data.get("preferred_skills", [])
                if pref_skills:
                    st.write(", ".join([f"`{s}`" for s in pref_skills]))
                else:
                    st.caption("No optional skills isolated.")

            with col_v2:
                st.markdown("#### 🎓 Qualifications & Compensation")
                degrees = parsed_data.get("required_degree_levels", [])
                st.markdown(f"**Degrees:** {', '.join(degrees) if degrees else 'Not Specified'}")

                fields_study = parsed_data.get("preferred_fields_of_study", [])
                st.markdown(f"**Fields of Study:** {', '.join(fields_study) if fields_study else 'Any Related Field'}")

                gpa = parsed_data.get("min_gpa_or_percentage")
                st.markdown(f"**Minimum GPA / Cutoff:** {gpa if gpa is not None else 'None Specified'}")

                certs = parsed_data.get("certifications_required", [])
                licenses = parsed_data.get("licenses_required", [])
                if certs or licenses:
                    st.markdown(f"**Credentials / Licenses:** {', '.join(certs + licenses)}")

                st.markdown("##### 💰 Compensation & Benefits")
                raw_comp = parsed_data.get("raw_compensation_text")
                if parsed_data.get("compensation_disclosed") and raw_comp:
                    st.success(f"Disclosed: **{raw_comp}**")
                else:
                    st.info("Compensation: Undisclosed")

                benefits = parsed_data.get("benefits", [])
                if benefits:
                    st.markdown(f"**Benefits Mentioned:** {', '.join(benefits)}")

            st.markdown("#### 📋 Responsibilities")
            resps = parsed_data.get("responsibilities", [])
            if resps:
                for r in resps[:8]:
                    st.markdown(f"- {r}")
                if len(resps) > 8:
                    st.caption(f"... and {len(resps) - 8} more items.")
            else:
                st.caption(selected_jd.raw_content[:400] + "..." if len(selected_jd.raw_content) > 400 else selected_jd.raw_content)

            with st.expander("🔎 View Raw Extracted Content & Field Provenance"):
                st.markdown("##### Field Provenance Audit")
                prov = parsed_data.get("field_provenance", {})
                if prov:
                    st.json(prov)
                st.markdown("##### Raw Ingested Text")
                st.text_area("Original Text", selected_jd.raw_content, height=200, disabled=True, key=f"raw_text_view_{selected_jd.id}")

        with sub_tab_edit:
            st.markdown("#### ✏️ Human Review & Correction Gate")
            st.caption(
                "Modify extracted details to ensure 100% accuracy. "
                "Saving creates a new immutable version snapshot linked to this original posting."
            )

            with st.form(f"edit_jd_form_{selected_jd.id}"):
                c_e1, c_e2 = st.columns(2)
                with c_e1:
                    edit_title = st.text_input("Position Title", value=selected_jd.job_title)
                    edit_company = st.text_input("Company Name", value=selected_jd.company_name)
                    edit_location = st.text_input("Location", value=parsed_data.get("location") or "")
                    edit_arrangement = st.selectbox(
                        "Work Arrangement",
                        options=["Remote", "Hybrid", "On-site", "Undisclosed"],
                        index=["Remote", "Hybrid", "On-site", "Undisclosed"].index(parsed_data.get("work_arrangement", "Undisclosed"))
                        if parsed_data.get("work_arrangement") in ["Remote", "Hybrid", "On-site", "Undisclosed"] else 3,
                    )
                with c_e2:
                    current_mand = ", ".join(parsed_data.get("mandatory_skills", []))
                    edit_mandatory = st.text_input("Mandatory Skills (comma-separated)", value=current_mand)

                    current_pref = ", ".join(parsed_data.get("preferred_skills", []))
                    edit_preferred = st.text_input("Preferred Skills (comma-separated)", value=current_pref)

                    edit_min_exp = st.number_input(
                        "Minimum Years Experience",
                        min_value=0.0,
                        max_value=30.0,
                        value=float(parsed_data.get("min_years_experience") or 0.0),
                        step=0.5,
                    )

                save_reviewed = st.form_submit_button("💾 Save Reviewed Snapshot", type="primary")

                if save_reviewed:
                    updated_data = dict(parsed_data)
                    updated_data["job_title"] = edit_title.strip()
                    updated_data["company_name"] = edit_company.strip()
                    updated_data["location"] = edit_location.strip()
                    updated_data["work_arrangement"] = edit_arrangement
                    updated_data["mandatory_skills"] = [s.strip() for s in edit_mandatory.split(",") if s.strip()]
                    updated_data["preferred_skills"] = [s.strip() for s in edit_preferred.split(",") if s.strip()]
                    updated_data["min_years_experience"] = edit_min_exp if edit_min_exp > 0 else None
                    updated_data["extraction_confidence"] = 1.0  # Confirmed by user

                    succ, msg, new_jd = service.update_job_snapshot(
                        user_id=user_id,
                        jd_id=selected_jd.id,
                        updated_parsed_data=updated_data,
                        new_job_title=edit_title.strip(),
                        new_company_name=edit_company.strip(),
                    )
                    if succ:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

        with sub_tab_lineage:
            st.markdown("#### 📜 Version Lineage & Audit Trail")
            st.caption("Immutable snapshot chain showing all revisions of this job description.")

            lineage = service.get_job_description_history(user_id=user_id, jd_id=selected_jd.id)
            for idx, hist_jd in enumerate(lineage):
                st.markdown(
                    f"**Revision {len(lineage) - idx}: Snapshot #{hist_jd.id}** — "
                    f"`{hist_jd.job_title}` at `{hist_jd.company_name}` "
                    f"({hist_jd.created_at}) "
                    f"[{'Active' if hist_jd.is_active else 'Superseded'}]"
                )

            st.divider()
            col_del1, _ = st.columns([1, 3])
            with col_del1:
                if st.button(f"🗑️ Delete Opportunity #{selected_jd.id}", type="secondary", key=f"btn_del_jd_{selected_jd.id}"):
                    succ, msg = service.delete_user_job_description(user_id=user_id, jd_id=selected_jd.id)
                    if succ:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

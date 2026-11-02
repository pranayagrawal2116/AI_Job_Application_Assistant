"""Application Preparer View: Resume parsing, job alignment, cover letter editing, screening questions, and human approval."""

from datetime import datetime
from pathlib import Path
import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from src.database.models import ApplicationStatus


def render_application_preparer():
    """Renders the end-to-end Application Preparation and Human Approval Interface."""
    st.markdown("## ✍️ Application Preparation & Human Approval Engine")
    st.caption("Parse verified resumes, align job requirements, customize cover letters, prepare screening answers, and authorize submissions under strict human governance.")

    service = DashboardService.get_instance()
    df_jobs = service.get_all_jobs_df()

    tab_resume, tab_align, tab_cover, tab_qa, tab_approval, tab_history = st.tabs([
        "📄 Resume Management",
        "🎯 Job-Resume Alignment",
        "✍️ Tailored Cover Letter",
        "💬 Screening Questions",
        "🛡️ Human Approval Gate",
        "📜 Prepared History",
    ])

    # =========================================================================
    # TAB 1: RESUME MANAGEMENT & PARSER
    # =========================================================================
    with tab_resume:
        st.markdown("### 📄 Resume Repository & Zero-Hallucination Parser")
        st.caption("Authoritative resume files stored in data/resumes/. Only verified details are extracted.")

        available_resumes = service.get_available_resumes()
        c1, c2 = st.columns([2, 1])

        with c1:
            if available_resumes:
                selected_resume = st.selectbox(
                    "Select Active Resume Document",
                    options=[f.name for f in available_resumes],
                    index=0,
                )
                selected_path = Path("data/resumes") / selected_resume

                col_btn1, col_btn2 = st.columns(2)
                with col_btn1:
                    if st.button("⚡ Parse & Synchronize Candidate Profile", type="primary"):
                        with st.spinner("Extracting resume details..."):
                            succ, msg, prof = service.sync_resume_file(selected_path)
                            if succ:
                                st.success(f"{msg} Recorded snapshot in SQLite.")
                                st.rerun()
                            else:
                                st.error(msg)
                with col_btn2:
                    st.caption(f"File Size: {selected_path.stat().st_size / 1024:.1f} KB")

            else:
                st.warning("No resume files found in data/resumes/. Please upload a resume below.")

        with c2:
            st.markdown("#### 📤 Upload New Resume")
            uploaded_file = st.file_uploader("Upload PDF or DOCX", type=["pdf", "docx"])
            if uploaded_file is not None:
                save_dest = Path("data/resumes") / uploaded_file.name
                with open(save_dest, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                st.success(f"Uploaded `{uploaded_file.name}`. Click 'Parse & Synchronize' above.")
                st.rerun()

        st.divider()

        # Display active profile details
        cand_prof = service.db.get_latest_candidate_profile()
        if cand_prof and cand_prof.profile_data:
            pdata = cand_prof.profile_data
            st.markdown(f"### 👤 Verified Candidate Profile (Version #{cand_prof.id})")
            personal = pdata.get("personal", {})
            col_p1, col_p2, col_p3 = st.columns(3)
            with col_p1:
                st.write(f"**Name:** {personal.get('full_name')}")
                st.write(f"**Email:** {personal.get('email')}")
                st.write(f"**Phone:** {personal.get('phone')}")
            with col_p2:
                edu = pdata.get("education", [{}])[0]
                st.write(f"**Institution:** {edu.get('institution')}")
                st.write(f"**Degree:** {edu.get('degree')}")
                st.write(f"**Graduation:** {edu.get('expected_graduation_year')} | **CGPA:** {edu.get('current_cgpa')}")
            with col_p3:
                meta = pdata.get("resume_metadata", {})
                st.write(f"**Source Document:** `{meta.get('source_file')}`")
                st.write(f"**File Hash:** `{meta.get('file_hash', '')[:16]}...`")
                st.write(f"**Extraction Date:** {meta.get('extraction_timestamp', '')[:19]}")

            col_exp, col_proj = st.columns(2)
            with col_exp:
                st.markdown("#### 💼 Work Experience")
                for exp in pdata.get("work_experience", []):
                    st.markdown(f"- **{exp.get('job_title')}** at *{exp.get('employer')}* ({exp.get('duration')})")
                    for r in exp.get("responsibilities", []):
                        st.caption(f"  • {r}")
            with col_proj:
                st.markdown("#### 🚀 Selected Projects")
                for prj in pdata.get("projects", []):
                    st.markdown(f"- **{prj.get('title')}**")
                    st.caption(f"  {prj.get('description')} *(Tech: {', '.join(prj.get('technologies', []))})*")

    # =========================================================================
    # TAB 2: JOB-RESUME ALIGNMENT
    # =========================================================================
    with tab_align:
        st.markdown("### 🎯 Job-Resume Alignment & Gap Analysis")
        st.caption("Examine how your verified experience maps against candidate job postings without fabricating unlisted skills.")

        if df_jobs.empty:
            st.info("No discovered jobs available.")
        else:
            # Let candidate select an opportunity
            job_options = {
                f"[{r['match_classification']}] {r['job_title']} at {r['company_name']} (#{r['id']})": r['id']
                for _, r in df_jobs.iterrows()
            }
            selected_label = st.selectbox("Select Target Opportunity", options=list(job_options.keys()))
            selected_job_id = job_options[selected_label]

            alignment = service.get_job_alignment(selected_job_id)
            if alignment:
                col_m1, col_m2, col_m3 = st.columns(3)
                with col_m1:
                    st.metric("Technical Match Coverage", f"{alignment.match_percentage:.1f}%")
                with col_m2:
                    st.metric("Matching Verified Skills", len(alignment.matching_skills))
                with col_m3:
                    st.metric("Identified Employer Gaps", len(alignment.missing_requirements))

                st.markdown("#### 📋 Tailored Alignment Summary")
                st.info(alignment.alignment_summary)

                c_match, c_missing = st.columns(2)
                with c_match:
                    st.markdown("#### ✅ Matching Technical Skills")
                    if alignment.matching_skills:
                        for s in alignment.matching_skills:
                            st.markdown(f"- 🟢 **{s}**")
                    else:
                        st.caption("No direct keyword match in verified profile.")
                with c_missing:
                    st.markdown("#### ⚠️ Missing Employer Requirements (Transparent Gap)")
                    if alignment.missing_requirements:
                        for m in alignment.missing_requirements:
                            st.markdown(f"- 🟡 **{m}** *(Requires rapid on-the-job adaptation)*")
                    else:
                        st.caption("No missing technical requirements detected.")

                st.markdown("#### 🚀 Recommended Focus Projects for this Role")
                for rp in alignment.relevant_projects:
                    st.markdown(f"- **{rp['title']}** — {rp['description']}")

    # =========================================================================
    # TAB 3: TAILORED COVER LETTER EDITOR
    # =========================================================================
    with tab_cover:
        st.markdown("### ✍️ Tailored Cover Letter Generator & Editor")
        st.caption("Generate bespoke, professional, and non-generic cover letters rooted exclusively in verified resume content.")

        if not df_jobs.empty:
            c_sel1, c_sel2 = st.columns([3, 1])
            with c_sel1:
                target_job_id = st.selectbox(
                    "Target Opportunity for Cover Letter",
                    options=list(job_options.keys()),
                    key="cover_job_select",
                )
                chosen_id = job_options[target_job_id]
            with c_sel2:
                st.write("")
                st.write("")
                gen_clicked = st.button("✨ Draft Tailored Letter", type="primary")

            # Store in session state for editing
            sess_key = f"cover_letter_{chosen_id}"
            if gen_clicked or sess_key not in st.session_state:
                with st.spinner("Generating personalized letter..."):
                    res = service.generate_cover_letter_for_job(chosen_id)
                    st.session_state[sess_key] = res["letter_text"]

            edited_letter = st.text_area(
                "Cover Letter Content (Markdown)",
                value=st.session_state[sess_key],
                height=450,
            )
            st.session_state[sess_key] = edited_letter

            col_sav1, col_sav2 = st.columns([1, 3])
            with col_sav1:
                if st.button("💾 Save Cover Letter Changes"):
                    out_dir = Path("data/exports/cover_letters")
                    out_dir.mkdir(parents=True, exist_ok=True)
                    clean_file = out_dir / f"cover_letter_job_{chosen_id}.md"
                    clean_file.write_text(edited_letter, encoding="utf-8")
                    service.update_application_notes(chosen_id, f"Custom cover letter saved at {clean_file.name}")
                    st.success(f"Cover letter saved to `{clean_file.name}`.")
            with col_sav2:
                st.download_button(
                    label="📥 Download Cover Letter (.md)",
                    data=edited_letter,
                    file_name=f"cover_letter_job_{chosen_id}.md",
                    mime="text/markdown",
                )

    # =========================================================================
    # TAB 4: SCREENING QUESTIONS & ANSWERS
    # =========================================================================
    with tab_qa:
        st.markdown("### 💬 Screening Question Responses")
        st.caption("Truthful answers grounded strictly in resume facts. Unknown questions are flagged as NEEDS CANDIDATE INPUT.")

        if not df_jobs.empty:
            target_qa_job = st.selectbox(
                "Select Opportunity for Question Preparation",
                options=list(job_options.keys()),
                key="qa_job_select",
            )
            qa_job_id = job_options[target_qa_job]
            questions = service.generate_questions_for_job(qa_job_id)

            for key, q_data in questions.items():
                with st.expander(f"❓ {q_data['question']}", expanded=False):
                    ans_val = st.text_area(
                        f"Response ({q_data['question']})",
                        value=q_data['answer'],
                        key=f"qa_{qa_job_id}_{key}",
                        height=120,
                    )
                    st.caption("Status: 🟢 Verified against Resume" if q_data['status'] == "READY" else "🟡 Needs Review")

            st.divider()
            st.markdown("#### 🧪 Test Custom Screening Question")
            user_custom_q = st.text_input("Enter arbitrary employer application question:")
            if user_custom_q:
                from src.preparer.question_answerer import QuestionAnswerer
                qa_engine = QuestionAnswerer()
                custom_res = qa_engine.answer_custom_question(user_custom_q)
                if custom_res["status"] == "NEEDS_CANDIDATE_INPUT":
                    st.warning(custom_res["answer"])
                else:
                    st.success(custom_res["answer"])

    # =========================================================================
    # TAB 5: HUMAN APPROVAL GATE
    # =========================================================================
    with tab_approval:
        st.markdown("### 🛡️ Human-in-the-Loop Application Authorization")
        st.caption("Strict safety safeguard: Applications are NEVER submitted automatically. Review the complete packet and authorize manually.")

        if not df_jobs.empty:
            target_app_job = st.selectbox(
                "Select Opportunity for Approval Review",
                options=list(job_options.keys()),
                key="approval_job_select",
            )
            app_job_id = job_options[target_app_job]
            job_obj = service.db.get_job_by_id(app_job_id)
            app_obj = service.db.get_application_by_job_id(app_job_id)
            current_status = app_obj.status.value if hasattr(app_obj.status, "value") else str(app_obj.status)

            st.info(f"**Current Application Status:** `{current_status}` | **Job ID:** #{app_job_id}")

            with st.container():
                st.markdown(f"#### 📦 Application Review Packet: {job_obj.company_name} — {job_obj.job_title}")
                st.write(f"**Official Application Portal:** [{job_obj.job_url}]({job_obj.job_url})")
                st.write(f"**Active Resume File:** `data/resumes/Pranay_Agrawal_Resume(2).pdf`")

                # Approval Checklist
                chk_details = st.checkbox("✅ I have reviewed the job description and confirmed eligibility.")
                chk_cover = st.checkbox("✅ I have inspected and approved the tailored cover letter.")
                chk_answers = st.checkbox("✅ I have reviewed the screening question responses.")
                chk_no_auto = st.checkbox("✅ I understand this system will NOT automatically submit the application.")

                approver_input = st.text_input("Human Approver Signature (Candidate Full Name):", value="Pranay Agrawal")

                col_app1, col_app2 = st.columns(2)
                with col_app1:
                    all_checked = chk_details and chk_cover and chk_answers and chk_no_auto
                    if st.button("🛡️ Grant Human Approval (Set Status -> Awaiting Approval)", type="primary"):
                        if not all_checked:
                            st.error("Please confirm all 4 review checklist items above.")
                        else:
                            succ, msg = service.authorize_application_packet(
                                job_id=app_job_id,
                                approver_name=approver_input,
                                candidate_confirmed=True,
                                cover_letter=st.session_state.get(f"cover_letter_{app_job_id}", "Tailored Letter"),
                                answers=service.generate_questions_for_job(app_job_id),
                            )
                            if succ:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)

                with col_app2:
                    st.markdown("#### 📬 Final Submission Confirmation")
                    st.caption("Once you manually complete submission on the employer portal:")
                    sub_notes = st.text_input("Submission Reference / Portal Confirmation Code:", key="sub_notes_in")
                    if st.button("✅ Confirm Manual Submission (Set Status -> Applied)"):
                        succ_sub, msg_sub = service.confirm_manual_submission(
                            job_id=app_job_id,
                            approver_name=approver_input,
                            submission_notes=sub_notes,
                        )
                        if succ_sub:
                            st.success(msg_sub)
                            st.rerun()
                        else:
                            st.error(msg_sub)

    # =========================================================================
    # TAB 6: PREPARED HISTORY
    # =========================================================================
    with tab_history:
        st.markdown("### 📜 Prepared Applications & Audit Trail")
        st.caption("History of applications prepared, human approvals granted, and audit actions logged in SQLite.")

        apps_df = df_jobs[df_jobs["application_status"].isin([
            ApplicationStatus.APPLICATION_PREPARED.value,
            ApplicationStatus.AWAITING_APPROVAL.value,
            ApplicationStatus.APPLIED.value,
            ApplicationStatus.INTERVIEW.value,
        ])]

        if apps_df.empty:
            st.info("No applications currently in 'Application Prepared', 'Awaiting Approval', or 'Applied' status.")
        else:
            st.dataframe(
                apps_df[["id", "company_name", "job_title", "platform", "match_score", "application_status"]],
                use_container_width=True,
            )

        st.divider()
        st.markdown("#### 🛡️ Complete SQLite Audit Trail (`application_logs`)")
        recent_logs = []
        for jid in df_jobs["id"].tolist()[:10]:
            logs = service.db.get_application_logs(jid)
            for l in logs:
                recent_logs.append({
                    "Job ID": l.job_id,
                    "Action": l.action,
                    "Timestamp": l.timestamp,
                    "Details": l.get_details_as_str()[:120],
                })
        if recent_logs:
            st.dataframe(recent_logs, use_container_width=True)
        else:
            st.caption("No audit entries logged yet.")


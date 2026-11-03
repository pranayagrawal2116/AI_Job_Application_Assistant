"""Application Preparer View: Universal multi-user resume tailoring, cover letter drafting,
screening question assistance, document generation, and human approval workflow.
"""

from __future__ import annotations

from pathlib import Path
import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from src.database.models import ApplicationStatus
from src.preparer.cover_letter_generator import CareerLevel, LetterTone
from src.preparer.document_generator import DocumentTemplate
from src.preparer.question_answerer import AnswerState, ScreeningQAPacket
from src.preparer.tailored_resume_generator import TailoredResume


def get_current_user_id() -> int:
    """Returns the authenticated user_id from session state."""
    return st.session_state.get("authenticated_user_id") or st.session_state.get("user_id") or 1


def render_application_preparer():
    """Renders the comprehensive 8-tab Universal Application Preparation & Document Generation Interface."""
    st.markdown("## ✍️ Universal Application Preparation & Document Generator")
    st.caption(
        "Prepare role-specific, ATS-optimized application materials for any profession. "
        "Strict zero-hallucination policy with claim-level auditability under human governance."
    )

    service = DashboardService.get_instance()
    user_id = get_current_user_id()

    # Load candidate's saved job descriptions and resumes
    user_jds = service.get_user_job_descriptions(user_id=user_id)
    user_resumes = service.get_user_resumes(user_id=user_id)
    db_profile = service.db.get_user_candidate_profile(user_id=user_id)
    candidate_profile = db_profile.get("profile_data", {}) if db_profile else {}

    # Define 8 professional workflow tabs
    tab_overview, tab_resume, tab_cover, tab_qa, tab_details, tab_attachments, tab_approval, tab_history = st.tabs([
        "🎯 Overview & Selection",
        "📄 Tailored Resume",
        "✍️ Tailored Cover Letter",
        "💬 Screening Questions",
        "📋 Application Details",
        "📎 Attachments Manifest",
        "🛡️ Review & Approval",
        "📜 Packet History & Downloads",
    ])

    # =========================================================================
    # TAB 1: OVERVIEW & SELECTION
    # =========================================================================
    with tab_overview:
        st.markdown("### 🎯 Application Workspace Setup")
        st.caption("Select your target job opportunity, source resume, and verified credentials to initialize the workspace.")

        col_s1, col_s2 = st.columns(2)
        with col_s1:
            if not user_jds:
                st.warning("⚠️ No saved job descriptions found. Add a job description in the 'Job Analyzer & Ingestion' view first.")
                selected_jd_id = None
            else:
                jd_options = {jd.id: f"{jd.company_name} — {jd.role_title} (#{jd.id})" for jd in user_jds}
                selected_jd_id = st.selectbox(
                    "Select Target Job Opportunity",
                    options=list(jd_options.keys()),
                    format_func=lambda x: jd_options[x],
                    key="prep_selected_jd",
                )

        with col_s2:
            if not user_resumes:
                st.warning("⚠️ No uploaded resumes found. Upload your resume in the 'Candidate Profile' view first.")
                selected_resume_id = None
            else:
                res_options = {
                    r["id"]: f"{r['original_filename']} ({r.get('label', 'General')}) v{r.get('active_version', 1)}"
                    for r in user_resumes
                }
                selected_resume_id = st.selectbox(
                    "Select Source Resume Document",
                    options=list(res_options.keys()),
                    format_func=lambda x: res_options[x],
                    key="prep_selected_resume",
                )

        if not selected_jd_id or not selected_resume_id:
            st.info("Please select both a target job description and a source resume to begin application preparation.")
            return

        selected_jd = service.get_job_description(user_id=user_id, jd_id=selected_jd_id)
        selected_res_meta = next((r for r in user_resumes if r["id"] == selected_resume_id), None)

        # Get or create application workspace
        app = service.get_or_create_application_workspace(
            user_id=user_id,
            job_description_id=selected_jd_id,
            resume_id=selected_resume_id,
        )

        st.divider()

        # Workspace Status Dashboard
        st.markdown(f"#### 💼 Active Application: **{app.job_title}** at **{app.company_name}**")
        c_m1, c_m2, c_m3, c_m4 = st.columns(4)
        with c_m1:
            st.metric("Application ID", f"#{app.id}")
        with c_m2:
            st.metric("Lifecycle Status", app.status)
        with c_m3:
            prof_status = "VERIFIED" if candidate_profile else "EMPTY"
            st.metric("Profile Status", prof_status)
        with c_m4:
            # Check latest match evaluation
            match_history = service.get_user_match_history(
                user_id=user_id,
                resume_id=selected_resume_id,
                job_description_id=selected_jd_id,
            )
            latest_match = match_history[0] if match_history else None
            match_score_str = f"{latest_match.match_score:.1f} / 100" if latest_match else "Not Evaluated"
            st.metric("Phase 5 Match Score", match_score_str)

        # Application Preparation Progress Checklist
        st.markdown("#### 📋 Application Preparation Progress")
        ch1 = "✅ Tailored Resume Prepared" if "tailored_resume" in st.session_state else "⏳ Tailored Resume (Tab 2)"
        ch2 = "✅ Cover Letter Drafted" if "cover_letter" in st.session_state else "⏳ Cover Letter (Tab 3)"
        ch3 = "✅ Screening Q&A Answered" if "qa_packet" in st.session_state else "⏳ Screening Q&A (Tab 4)"
        ch4 = "✅ Human Approved" if app.status in [ApplicationStatus.AWAITING_APPROVAL.value, ApplicationStatus.APPLIED.value] else "⏳ Review & Approval (Tab 7)"

        st.write(f"- {ch1}")
        st.write(f"- {ch2}")
        st.write(f"- {ch3}")
        st.write(f"- {ch4}")

    # =========================================================================
    # TAB 2: TAILORED RESUME
    # =========================================================================
    with tab_resume:
        st.markdown("### 📄 Role-Specific Tailored Resume Generator")
        st.caption(
            "Synthesizes an ATS-optimized, factual resume highlighting relevant skills and experiences. "
            "Never fabricates degrees, metrics, dates, or employers."
        )

        col_t1, col_t2 = st.columns([2, 1])
        with col_t1:
            custom_instructions = st.text_input(
                "Optional Tailoring Instructions",
                placeholder="e.g. Highlight healthcare compliance experience, prioritize leadership responsibilities",
                key="tailor_instructions",
            )
        with col_t2:
            st.write("")
            st.write("")
            gen_resume_btn = st.button("⚡ Generate Tailored Resume", type="primary", use_container_width=True)

        if gen_resume_btn or "tailored_resume" not in st.session_state:
            with st.spinner("Analyzing job requirements and tailoring verified credentials..."):
                jd_dict = {
                    "id": selected_jd.id if selected_jd else None,
                    "company_name": selected_jd.company_name if selected_jd else app.company_name,
                    "role_title": selected_jd.role_title if selected_jd else app.job_title,
                    "required_skills": selected_jd.required_skills if selected_jd else [],
                    "preferred_skills": selected_jd.preferred_skills if selected_jd else [],
                }
                match_dict = latest_match.to_dict() if latest_match else None
                tailored: TailoredResume = service.generate_tailored_resume(
                    user_id=user_id,
                    candidate_profile=candidate_profile,
                    resume_data=selected_res_meta,
                    job_description=jd_dict,
                    match_result=match_dict,
                    custom_instructions=custom_instructions or None,
                )
                st.session_state["tailored_resume"] = tailored

        tailored: TailoredResume = st.session_state["tailored_resume"]

        # Display Structured Tailored Resume
        st.markdown(f"#### 👤 {tailored.personal_info.get('full_name', 'Candidate')} — {tailored.target_role}")
        st.caption(f"Targeting: **{tailored.target_company}** | Tailored Resume Version: **v{tailored.version}**")

        if tailored.professional_summary:
            with st.expander("📝 Professional Summary", expanded=True):
                st.write(tailored.professional_summary)
                if tailored.summary_provenance:
                    st.caption(
                        f"🔒 Provenance: `{tailored.summary_provenance.source_type}` | "
                        f"Evidence Status: `{tailored.summary_provenance.evidence_status}` | "
                        f"Confidence: `{tailored.summary_provenance.confidence * 100:.0f}%`"
                    )

        with st.expander("🛠️ Highlighted Skills & Capabilities", expanded=True):
            if tailored.matching_skills:
                st.markdown(f"**🎯 Target Role Focus:** {', '.join(tailored.matching_skills)}")
            for cat, skl in tailored.skills_by_category.items():
                if skl:
                    st.markdown(f"**{cat}:** {', '.join(skl)}")

        # Work Experience & Bullet Editor
        st.markdown("#### 💼 Professional Experience & Bullet Alignment")
        for e_idx, exp in enumerate(tailored.experience_entries):
            dur_txt = f" ({exp.duration})" if exp.duration else ""
            with st.expander(f"🏢 {exp.job_title} at {exp.employer}{dur_txt}", expanded=True):
                for b_idx, bullet in enumerate(exp.bullets):
                    c_b1, c_b2 = st.columns([4, 1])
                    with c_b1:
                        new_txt = st.text_input(
                            f"Bullet {b_idx + 1}",
                            value=bullet.bullet_text,
                            key=f"bullet_{e_idx}_{b_idx}",
                        )
                        if new_txt != bullet.bullet_text:
                            tailored.update_bullet(e_idx, b_idx, new_txt)
                            st.session_state["tailored_resume"] = tailored
                            st.rerun()
                    with c_b2:
                        st.caption(f"Score: `{bullet.relevance_score:.1f}`")
                        st.caption(f"Status: `{bullet.provenance.evidence_status}`")

        # Unified Diff Viewer
        with st.expander("🔍 Inspect Diff Against Original Experience Bullets"):
            orig_bullets = []
            for exp in candidate_profile.get("work_experience", []):
                for r in exp.get("responsibilities", []):
                    orig_bullets.append(str(r).strip())
            diff_lines = tailored.diff_with_original(orig_bullets)
            if diff_lines:
                st.code("\n".join(diff_lines), language="diff")
            else:
                st.info("No text modifications detected from original responsibilities.")

    # =========================================================================
    # TAB 3: TAILORED COVER LETTER
    # =========================================================================
    with tab_cover:
        st.markdown("### ✍️ Evidence-Backed Tailored Cover Letter")
        st.caption("Crafts a compelling, professional cover letter matching your target company and career level.")

        c_cl1, c_cl2, c_cl3 = st.columns(3)
        with c_cl1:
            selected_tone_name = st.selectbox(
                "Tone & Style",
                options=[t.value for t in LetterTone],
                index=0,
                key="cl_tone_select",
            )
            selected_tone = next(t for t in LetterTone if t.value == selected_tone_name)
        with c_cl2:
            selected_level_name = st.selectbox(
                "Career Progression Level",
                options=[c.value for c in CareerLevel],
                index=1,
                key="cl_level_select",
            )
            selected_level = next(c for c in CareerLevel if c.value == selected_level_name)
        with c_cl3:
            st.write("")
            st.write("")
            gen_cover_btn = st.button("🚀 Draft Tailored Cover Letter", type="primary", use_container_width=True)

        if gen_cover_btn or "cover_letter" not in st.session_state:
            with st.spinner("Synthesizing personalized cover letter from verified qualifications..."):
                jd_dict = {
                    "company_name": selected_jd.company_name if selected_jd else app.company_name,
                    "role_title": selected_jd.role_title if selected_jd else app.job_title,
                }
                match_dict = latest_match.to_dict() if latest_match else None
                cl = service.generate_universal_cover_letter(
                    user_id=user_id,
                    candidate_profile=candidate_profile,
                    job_description=jd_dict,
                    resume_data=selected_res_meta,
                    match_result=match_dict,
                    tone=selected_tone,
                    career_level=selected_level,
                )
                st.session_state["cover_letter"] = cl

        cl = st.session_state["cover_letter"]

        # Live Editable Cover Letter Text
        st.markdown("#### 📄 Editable Cover Letter Draft")
        edited_letter_text = st.text_area(
            "Review and edit your cover letter before approval:",
            value=cl.letter_text,
            height=350,
            key="cover_letter_editor",
        )
        if edited_letter_text != cl.letter_text:
            cl.letter_text = edited_letter_text
            st.session_state["cover_letter"] = cl

        # Claim Provenance Inspector
        with st.expander("🔒 Inspect Claim Provenance & Evidence Sources"):
            for idx, claim in enumerate(cl.provenance_claims, start=1):
                st.write(f"**Paragraph {idx} Claim (`{claim.claim_id}`):**")
                st.caption(f"Source: `{claim.source_type}` ({claim.source_field}) | Status: `{claim.evidence_status}`")

    # =========================================================================
    # TAB 4: SCREENING QUESTIONS
    # =========================================================================
    with tab_qa:
        st.markdown("### 💬 Screening Question Answer Assistant")
        st.caption(
            "Drafts truthful responses across 19 standard categories. "
            "Any subjective, salary, notice period, or missing items are strictly flagged as NEEDS CANDIDATE INPUT."
        )

        with st.form("add_screening_questions_form"):
            questions_input = st.text_area(
                "Paste Employer Screening Questions (one per line):",
                placeholder="What is your expected salary?\nHow many years of experience do you have with Python?\nWhy do you want to join our team?\nAre you willing to relocate?",
                height=100,
            )
            char_limit_input = st.number_input("Character Limit per Answer (0 for none)", min_value=0, max_value=5000, value=0)
            qa_submit = st.form_submit_button("⚡ Answer Screening Questions", type="primary")

        if qa_submit and questions_input.strip():
            with st.spinner("Classifying and generating evidence-grounded answers..."):
                jd_dict = {
                    "company_name": selected_jd.company_name if selected_jd else app.company_name,
                    "role_title": selected_jd.role_title if selected_jd else app.job_title,
                }
                char_lim = int(char_limit_input) if char_limit_input > 0 else None
                answered_list = service.batch_answer_screening_questions(
                    questions=questions_input,
                    user_id=user_id,
                    candidate_profile=candidate_profile,
                    resume_data=selected_res_meta,
                    job_description=jd_dict,
                    character_limit=char_lim,
                )
                qa_packet = ScreeningQAPacket(
                    user_id=user_id,
                    job_description_id=selected_jd_id,
                    questions=answered_list,
                )
                st.session_state["qa_packet"] = qa_packet
                st.success(f"Generated responses for {len(answered_list)} questions!")

        # Initialize default standard questions if empty
        if "qa_packet" not in st.session_state:
            default_qs = [
                f"Why do you want to work at {selected_jd.company_name if selected_jd else app.company_name}?",
                "What is your expected compensation?",
                "What is your earliest available start date?",
                "Are you legally authorized to work in this location?",
            ]
            answered_defaults = service.batch_answer_screening_questions(
                questions=default_qs,
                user_id=user_id,
                candidate_profile=candidate_profile,
                resume_data=selected_res_meta,
                job_description={"company_name": app.company_name, "role_title": app.job_title},
            )
            st.session_state["qa_packet"] = ScreeningQAPacket(
                user_id=user_id,
                job_description_id=selected_jd_id,
                questions=answered_defaults,
            )

        qa_packet: ScreeningQAPacket = st.session_state["qa_packet"]

        st.markdown(f"#### 📋 Questions ({len(qa_packet.questions)} Total)")
        for q_idx, q in enumerate(qa_packet.questions):
            badge = "🟢 READY" if q.state in [AnswerState.GENERATED_DRAFT.value, AnswerState.USER_APPROVED.value] else "🟡 NEEDS INPUT"
            with st.expander(f"Q{q_idx + 1}: **{q.question_text}** — {badge} [{q.category}]", expanded=(q.state == AnswerState.NEEDS_CANDIDATE_INPUT.value)):
                st.caption(f"Category: **{q.category}** | Current Review State: `{q.state}`")
                new_ans = st.text_area(
                    "Answer",
                    value=q.answer_text,
                    key=f"ans_editor_{q_idx}",
                    height=80,
                )
                if q.character_limit:
                    curr_len = len(new_ans)
                    st.caption(f"Character Count: {curr_len} / {q.character_limit}")

                col_qa1, col_qa2 = st.columns([2, 2])
                with col_qa1:
                    if st.button("💾 Save Answer & Mark Approved", key=f"app_q_{q_idx}"):
                        q.answer_text = new_ans.strip()
                        q.state = AnswerState.USER_APPROVED.value
                        st.session_state["qa_packet"] = qa_packet
                        st.success("Answer confirmed and approved!")
                        st.rerun()

    # =========================================================================
    # TAB 5: APPLICATION DETAILS
    # =========================================================================
    with tab_details:
        st.markdown("### 📋 Candidate Logistics & Application Preferences")
        st.caption("Update confirmed logistics and personal preferences for this opportunity.")

        cand_inputs = candidate_profile.get("candidate_inputs", {})
        with st.form("candidate_logistics_form"):
            cl_1, cl_2 = st.columns(2)
            with cl_1:
                stipend_val = st.text_input("Expected Compensation / Stipend", value=cand_inputs.get("expected_stipend") or "")
                avail_val = st.text_input("Earliest Start Date / Availability", value=cand_inputs.get("internship_availability") or "")
                notice_val = st.text_input("Notice Period", value=cand_inputs.get("notice_period") or "")
            with cl_2:
                reloc_val = st.text_input("Relocation Preference", value=cand_inputs.get("relocation_willingness") or "")
                mode_val = st.text_input("Work Mode Preference (Remote / Hybrid / On-site)", value=cand_inputs.get("work_mode_preference") or "")
                hours_val = st.text_input("Weekly Available Hours", value=cand_inputs.get("weekly_working_hours") or "")

            save_logistics_btn = st.form_submit_button("💾 Save Logistics to Profile")
            if save_logistics_btn:
                updated_inputs = dict(cand_inputs)
                updated_inputs["expected_stipend"] = stipend_val.strip()
                updated_inputs["internship_availability"] = avail_val.strip()
                updated_inputs["notice_period"] = notice_val.strip()
                updated_inputs["relocation_willingness"] = reloc_val.strip()
                updated_inputs["work_mode_preference"] = mode_val.strip()
                updated_inputs["weekly_working_hours"] = hours_val.strip()

                candidate_profile["candidate_inputs"] = updated_inputs
                service.db.save_user_candidate_profile(user_id=user_id, profile_data=candidate_profile)
                st.success("Candidate logistics recorded in profile!")
                st.rerun()

    # =========================================================================
    # TAB 6: ATTACHMENTS MANIFEST
    # =========================================================================
    with tab_attachments:
        st.markdown("### 📎 Application Attachments Manifest")
        st.caption("Cryptographically tracks all supporting documents and deliverables for this application packet.")

        attachments = [
            {"name": f"Original Resume ({selected_res_meta.get('original_filename', 'Resume')})", "type": "Source Document", "format": selected_res_meta.get("file_format", "PDF").upper(), "size_kb": f"{(selected_res_meta.get('file_size_bytes', 0) / 1024):.1f} KB"},
            {"name": "Tailored Resume (Generated)", "type": "Application Material", "format": "PDF / DOCX", "size_kb": "Auto-calculated"},
            {"name": "Tailored Cover Letter (Generated)", "type": "Application Material", "format": "PDF / DOCX", "size_kb": "Auto-calculated"},
            {"name": "Screening Questions & Responses", "type": "Application Material", "format": "PDF / DOCX", "size_kb": "Auto-calculated"},
        ]
        st.table(attachments)

    # =========================================================================
    # TAB 7: REVIEW & APPROVAL GATE
    # =========================================================================
    with tab_approval:
        st.markdown("### 🛡️ Human Audit & Authorization Gate")
        st.caption(
            "Strict human governance: automated agents are strictly forbidden from submitting applications. "
            "You must inspect all generated documents and authorize this application."
        )

        # 1. Document Template Selector & Export
        st.markdown("#### 1. Generate Official PDF & Word DOCX Files")
        col_tmpl1, col_tmpl2 = st.columns([3, 2])
        with col_tmpl1:
            tmpl_name = st.selectbox(
                "Document Layout & Typography Style",
                options=[t.value for t in DocumentTemplate],
                index=0,
                key="doc_template_select",
            )
            doc_template = next(t for t in DocumentTemplate if t.value == tmpl_name)
        with col_tmpl2:
            st.write("")
            st.write("")
            export_docs_btn = st.button("📥 Generate & Validate PDF/DOCX Files", type="primary", use_container_width=True)

        if export_docs_btn or "generated_docs" not in st.session_state:
            with st.spinner("Generating ATS-optimized PDF and DOCX files..."):
                docs = service.export_application_documents(
                    user_id=user_id,
                    application_id=app.id,
                    resume=tailored,
                    cover_letter=cl,
                    qa_packet=qa_packet,
                    template=doc_template,
                )
                st.session_state["generated_docs"] = docs
                st.success("Successfully generated and structurally validated all application documents!")

        docs = st.session_state.get("generated_docs", {})

        # 2. Assemble Prepared Packet in SQLite
        st.markdown("#### 2. Assemble Immutable Prepared Packet")
        c_pk1, c_pk2 = st.columns([3, 1])
        with c_pk1:
            st.caption("Bundles the tailored resume, cover letter, screening answers, and attachment hashes into an immutable version snapshot.")
        with c_pk2:
            prep_packet_btn = st.button("📦 Assemble Packet", use_container_width=True)

        if prep_packet_btn or "prepared_packet" not in st.session_state:
            with st.spinner("Assembling RFC 8785 canonical packet snapshot..."):
                res_hash = selected_res_meta.get("file_hash", "")
                jd_hash = selected_jd.content_hash if selected_jd else "jd_hash"
                pkt = service.prepare_universal_application_packet(
                    user_id=user_id,
                    application_id=app.id,
                    original_resume_id=selected_resume_id,
                    original_resume_hash=res_hash,
                    tailored_resume=tailored,
                    cover_letter=cl,
                    qa_packet=qa_packet,
                    job_description_snapshot_hash=jd_hash,
                    tailored_resume_doc=docs.get("resume_pdf"),
                    cover_letter_doc=docs.get("cover_letter_pdf"),
                )
                st.session_state["prepared_packet"] = pkt
                st.success(f"Immutable Packet #{pkt.id} (Version {pkt.version_num}) recorded in SQLite!")

        pkt = st.session_state.get("prepared_packet")
        if pkt:
            st.info(f"Active Packet Hash (SHA-256): `{pkt.packet_version_hash}`")

        st.divider()

        # 3. Human Authorization Gate Form
        st.markdown("#### 3. Authorize Application for Submission")
        with st.form("human_authorization_form"):
            approver_name_input = st.text_input(
                "Full Name of Human Approver",
                value=candidate_profile.get("personal", {}).get("full_name") or "",
                placeholder="e.g. Alice Smith",
            )
            confirm_truthfulness = st.checkbox(
                "I explicitly confirm that I have reviewed all generated materials, the information is completely truthful, and I authorize this application.",
                value=False,
            )

            auth_submit = st.form_submit_button("🛡️ Grant Human Authorization", type="primary")

            if auth_submit:
                if not confirm_truthfulness:
                    st.error("You must check the confirmation checkbox to authorize.")
                elif not approver_name_input.strip():
                    st.error("Approver full name is required.")
                else:
                    # Issue cryptographic single-use ticket
                    sess = service.get_or_create_candidate_session(candidate_name=approver_name_input.strip(), candidate_id=f"user_{user_id}")
                    action_ticket = service.issue_approval_ticket(
                        session_id=sess.session_id,
                        job_id=app.id,
                        packet_hash=pkt.packet_version_hash,
                    )
                    succ, msg, approval = service.authorize_universal_application_packet(
                        user_id=user_id,
                        application_id=app.id,
                        packet_id=pkt.id,
                        approver_name=approver_name_input.strip(),
                        session_id=sess.session_id,
                        action_ticket=action_ticket,
                        candidate_confirmed=confirm_truthfulness,
                    )
                    if succ:
                        st.success(f"✅ {msg}")
                        st.rerun()
                    else:
                        st.error(f"Authorization failed: {msg}")

    # =========================================================================
    # TAB 8: PACKET HISTORY & DOWNLOADS
    # =========================================================================
    with tab_history:
        st.markdown("### 📜 Application Packet Revisions & Downloads")
        st.caption("Immutable version history of all prepared packets and official downloadable documents.")

        revisions = service.list_application_packets(application_id=app.id, user_id=user_id)
        if not revisions:
            st.info("No prepared packet revisions recorded for this application yet.")
        else:
            for rev in revisions:
                is_act = bool(rev.is_active_revision)
                act_badge = " ⭐ **[ACTIVE REVISION]**" if is_act else ""
                with st.expander(f"📦 Packet v{rev.version_num} — Created: {rev.created_at}{act_badge}", expanded=is_act):
                    st.caption(f"Packet SHA-256: `{rev.packet_version_hash}`")
                    st.caption(f"Original Resume ID: `#{rev.original_resume_id}` (Hash: `{rev.original_resume_hash[:16]}...`)")

                    # Download Buttons for Generated Documents
                    if is_act and "generated_docs" in st.session_state:
                        g_docs = st.session_state["generated_docs"]
                        st.markdown("##### ⬇️ Download Official Documents")
                        cd1, cd2, cd3, cd4 = st.columns(4)
                        with cd1:
                            r_pdf = g_docs.get("resume_pdf")
                            if r_pdf and Path(r_pdf.file_path).exists():
                                st.download_button("📄 Resume (PDF)", data=Path(r_pdf.file_path).read_bytes(), file_name=f"Tailored_Resume_{app.company_name}.pdf", mime="application/pdf")
                        with cd2:
                            r_docx = g_docs.get("resume_docx")
                            if r_docx and Path(r_docx.file_path).exists():
                                st.download_button("📄 Resume (Word)", data=Path(r_docx.file_path).read_bytes(), file_name=f"Tailored_Resume_{app.company_name}.docx", mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
                        with cd3:
                            c_pdf = g_docs.get("cover_letter_pdf")
                            if c_pdf and Path(c_pdf.file_path).exists():
                                st.download_button("✍️ Cover Letter (PDF)", data=Path(c_pdf.file_path).read_bytes(), file_name=f"Cover_Letter_{app.company_name}.pdf", mime="application/pdf")
                        with cd4:
                            p_pdf = g_docs.get("packet_pdf")
                            if p_pdf and Path(p_pdf.file_path).exists():
                                st.download_button("📦 Full Packet (PDF)", data=Path(p_pdf.file_path).read_bytes(), file_name=f"Application_Packet_{app.company_name}.pdf", mime="application/pdf")

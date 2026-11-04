"""Candidate Application Tracker UI Presentation Components (Phase 7.3.2.3).

Provides reusable, modular presentation helpers for:
- Header & Authoritative KPI Metrics
- Follow-up alert bar & reminder manager
- Filter toolbar & CSV export
- Application detail tabs (Overview, Match Evaluation, Timeline, Prepared Packets, Transitions, Follow-ups, Archive)
- Five-column canonical Kanban board
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import UTC, datetime
from typing import Any

import streamlit as st

from dashboard.services.dashboard_service import DashboardService
from src.database.exceptions import (
    DatabaseError,
    InvalidStatusTransitionError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.database.models import (
    Application,
    ApplicationFollowUp,
    ApplicationStatus,
    FollowUpType,
    SubmissionChannel,
)
from src.lifecycle.follow_up_engine import SUPPORTED_TEMPLATE_TYPES
from src.lifecycle.state_machine import ApplicationStateMachine

# =============================================================================
# STATUS BADGES & CANONICAL GROUPINGS
# =============================================================================

STATUS_COLOR_MAP: dict[str, str] = {
    "DRAFT": "#6B7280",              # Gray
    "PREPARING": "#3B82F6",          # Blue
    "READY_FOR_REVIEW": "#8B5CF6",   # Purple
    "APPROVED": "#06B6D4",           # Cyan
    "SUBMITTED": "#1D4ED8",          # Deep Blue
    "IN_PROGRESS": "#F59E0B",        # Amber
    "ASSESSMENT": "#F97316",         # Orange
    "INTERVIEW": "#6366F1",          # Indigo
    "OFFER": "#10B981",              # Emerald Green
    "REJECTED": "#EF4444",           # Red
    "WITHDRAWN": "#64748B",          # Slate
    "CLOSED": "#4B5563",             # Dark Gray
}

KANBAN_COLUMNS: list[dict[str, Any]] = [
    {
        "id": "col_prep",
        "title": "1. Preparation",
        "statuses": [ApplicationStatus.DRAFT.value, ApplicationStatus.PREPARING.value],
        "description": "Drafting and tailoring materials",
    },
    {
        "id": "col_review",
        "title": "2. Review & Approval",
        "statuses": [ApplicationStatus.READY_FOR_REVIEW.value, ApplicationStatus.APPROVED.value],
        "description": "Ready for candidate audit & human approval",
    },
    {
        "id": "col_submitted",
        "title": "3. Submitted & Active",
        "statuses": [ApplicationStatus.SUBMITTED.value, ApplicationStatus.IN_PROGRESS.value],
        "description": "Submitted to employer, awaiting next step",
    },
    {
        "id": "col_assessment",
        "title": "4. Assessment & Interviews",
        "statuses": [ApplicationStatus.ASSESSMENT.value, ApplicationStatus.INTERVIEW.value, ApplicationStatus.OFFER.value],
        "description": "Screening tests, interviews, and active offers",
    },
    {
        "id": "col_concluded",
        "title": "5. Concluded",
        "statuses": [ApplicationStatus.REJECTED.value, ApplicationStatus.WITHDRAWN.value, ApplicationStatus.CLOSED.value],
        "description": "Final outcomes and closed opportunities",
    },
]


def format_status_badge(status_str: str) -> str:
    """Formats a canonical status with human-readable styling."""
    try:
        norm = ApplicationStateMachine.normalize_status(status_str).value
    except (KeyError, ValueError, AttributeError):
        norm = status_str.upper()
    return f"`{norm}`"


# =============================================================================
# CSV EXPORT HELPER & FORMULA INJECTION SANITIZATION
# =============================================================================

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(val: Any) -> Any:
    """Sanitizes text values to prevent spreadsheet formula injection (CSV Injection).

    If a text value begins with '=', '+', '-', '@', tab, or carriage return
    (or has formula trigger characters after leading whitespace), prefixes it
    with a single quote (') so spreadsheet processors treat it as a string literal.
    Preserves numbers, booleans, None, and safe text unaltered.
    """
    if val is None:
        return ""
    if not isinstance(val, str):
        return val
    if not val:
        return ""
    if val.startswith(FORMULA_PREFIXES):
        return "'" + val
    stripped = val.lstrip()
    if stripped and stripped.startswith(("=", "+", "-", "@")):
        return "'" + val
    return val


def build_tracker_csv_export(applications: list[Application]) -> str:
    """Serializes candidate-owned applications into CSV format.

    Excludes all tokens, action tickets, secrets, and internal filesystem paths.
    Sanitizes untrusted text values against formula injection.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    headers = [
        "id",
        "company_name",
        "job_title",
        "status",
        "target_role",
        "employment_type",
        "location",
        "salary_range",
        "application_deadline",
        "date_prepared",
        "date_submitted",
        "created_at",
        "updated_at",
        "is_archived",
    ]
    writer.writerow(headers)

    for app in applications:
        writer.writerow([
            app.id,
            sanitize_csv_cell(app.company_name),
            sanitize_csv_cell(app.job_title),
            sanitize_csv_cell(app.status),
            sanitize_csv_cell(app.target_role),
            sanitize_csv_cell(app.employment_type),
            sanitize_csv_cell(app.location),
            sanitize_csv_cell(app.salary_range),
            sanitize_csv_cell(app.application_deadline),
            sanitize_csv_cell(app.date_prepared),
            sanitize_csv_cell(app.date_submitted),
            sanitize_csv_cell(app.created_at),
            sanitize_csv_cell(app.updated_at),
            bool(app.is_archived),
        ])

    return output.getvalue()


# =============================================================================
# 1. HEADER & KPI METRICS BAR
# =============================================================================

def render_tracker_header(user_id: int) -> None:
    """Renders the top title, subtitle, and navigation hint."""
    st.markdown("## 📋 Candidate Application Tracker")
    st.caption("Monitor and manage your applications from preparation through interviews, offers, and final outcomes.")


def render_tracker_metrics_bar(metrics: dict[str, int]) -> None:
    """Renders the authoritative 10 KPI metric cards directly from backend keys."""
    # Row 1: Pipeline Pipeline Stages
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric(label="Total Tracked", value=metrics.get("total", 0))
    with col2:
        st.metric(label="In Preparation", value=metrics.get("in_preparation", 0))
    with col3:
        st.metric(label="Approved", value=metrics.get("approved", 0))
    with col4:
        st.metric(label="Submitted", value=metrics.get("submitted", 0))
    with col5:
        st.metric(label="In Progress", value=metrics.get("in_progress", 0))

    # Row 2: Evaluation, Outcomes & Actions
    col6, col7, col8, col9, col10 = st.columns(5)
    with col6:
        st.metric(label="Interviewing", value=metrics.get("interviewing", 0))
    with col7:
        st.metric(label="Offers", value=metrics.get("offers", 0))
    with col8:
        st.metric(label="Active Pipeline", value=metrics.get("active_pipeline", 0))
    with col9:
        st.metric(label="Concluded", value=metrics.get("concluded", 0))
    with col10:
        st.metric(label="Follow-ups Due", value=metrics.get("follow_ups_due", 0))


# =============================================================================
# 2. FOLLOW-UP ALERT BAR
# =============================================================================

def render_follow_up_alert_bar(
    service: DashboardService,
    session_id: str,
    user_id: int,
    pending_follow_ups: list[ApplicationFollowUp],
    app_map: dict[int, Application],
) -> None:
    """Renders pending reminders alert bar with quick Mark Complete actions."""
    if not pending_follow_ups:
        st.info("You have no outstanding follow-up reminders.")
        return

    today_str = datetime.now(UTC).strftime("%Y-%m-%d")
    overdue_count = sum(1 for f in pending_follow_ups if f.follow_up_date < today_str)
    today_count = sum(1 for f in pending_follow_ups if f.follow_up_date == today_str)

    summary_parts = []
    if overdue_count > 0:
        summary_parts.append(f"⚠️ {overdue_count} Overdue")
    if today_count > 0:
        summary_parts.append(f"🔔 {today_count} Due Today")
    summary_text = " | ".join(summary_parts) if summary_parts else f"📅 {len(pending_follow_ups)} Upcoming"

    with st.expander(f"🔔 Pending Follow-Up Reminders ({summary_text})", expanded=True):
        for f in pending_follow_ups:
            app = app_map.get(f.application_id)
            company = app.company_name if app else f"App #{f.application_id}"
            title = app.job_title if app else "Role"

            is_overdue = f.follow_up_date < today_str
            is_today = f.follow_up_date == today_str
            badge = "🚨 OVERDUE" if is_overdue else ("🔔 DUE TODAY" if is_today else "📅 UPCOMING")

            col_info, col_action = st.columns([4, 2])
            with col_info:
                st.markdown(f"**{badge}** • `{f.follow_up_date}` • **{company}** — *{title}*")
                st.caption(f"**Type:** {f.follow_up_type} | **Task:** {f.description}")

            with col_action:
                complete_key = f"alert_comp_btn_{user_id}_{f.id}"
                notes_key = f"alert_comp_notes_{user_id}_{f.id}"
                with st.popover("Mark Complete"):
                    outcome = st.text_input("Outcome Notes (Optional)", key=notes_key)
                    if st.button("Confirm Completed", key=complete_key):
                        try:
                            service.complete_application_follow_up(
                                session_id=session_id,
                                follow_up_id=f.id,
                                outcome_notes=outcome.strip() if outcome else None,
                            )
                            st.success("Reminder marked complete.")
                            st.rerun()
                        except (DatabaseError, KeyError, ValueError) as exc:
                            st.error(f"Error completing reminder: {exc}")


# =============================================================================
# 3. FILTER TOOLBAR & CONTROLS
# =============================================================================

def render_tracker_filter_toolbar(
    user_id: int,
    applications_for_export: list[Application],
) -> dict[str, Any]:
    """Renders the view switcher, search, category filter, sort, and export controls."""
    col_view, col_search, col_cat, col_emp, col_sort, col_actions = st.columns([2, 3, 2, 2, 2, 2])

    with col_view:
        view_mode = st.radio(
            "View Mode",
            options=["List View", "Kanban Board"],
            horizontal=True,
            key=f"tracker_view_mode_{user_id}",
        )

    with col_search:
        search_term = st.text_input(
            "Search Applications",
            placeholder="Search by company or role...",
            key=f"tracker_search_{user_id}",
        )

    with col_cat:
        category_options = [
            "All Statuses",
            "Preparation",
            "Review & Approval",
            "Submitted & Active",
            "Assessment & Offers",
            "Concluded",
        ]
        selected_category = st.selectbox(
            "Status Category",
            options=category_options,
            key=f"tracker_category_{user_id}",
        )

    with col_emp:
        emp_options = ["All Types", "Full-time", "Part-time", "Contract", "Internship", "Temporary"]
        selected_emp = st.selectbox(
            "Employment Type",
            options=emp_options,
            key=f"tracker_emp_type_{user_id}",
        )

    with col_sort:
        sort_display_map = {
            "Last Updated (Newest)": "updated_at_desc",
            "Created Date (Newest)": "created_at_desc",
            "Created Date (Oldest)": "created_at_asc",
            "Deadline (Earliest)": "deadline_asc",
            "Company Name (A-Z)": "company_name_asc",
            "Job Title (A-Z)": "job_title_asc",
        }
        selected_sort_label = st.selectbox(
            "Sort Order",
            options=list(sort_display_map.keys()),
            key=f"tracker_sort_{user_id}",
        )
        sort_by = sort_display_map[selected_sort_label]

    with col_actions:
        include_archived = st.checkbox(
            "Include Archived",
            value=False,
            key=f"tracker_include_archived_{user_id}",
        )
        csv_data = build_tracker_csv_export(applications_for_export)
        st.download_button(
            label="📥 Export CSV",
            data=csv_data,
            file_name=f"candidate_applications_{user_id}.csv",
            mime="text/csv",
            key=f"tracker_csv_btn_{user_id}",
        )

    # Map category to status_in list
    status_in: list[str] | None = None
    if selected_category == "Preparation":
        status_in = [ApplicationStatus.DRAFT.value, ApplicationStatus.PREPARING.value]
    elif selected_category == "Review & Approval":
        status_in = [ApplicationStatus.READY_FOR_REVIEW.value, ApplicationStatus.APPROVED.value]
    elif selected_category == "Submitted & Active":
        status_in = [ApplicationStatus.SUBMITTED.value, ApplicationStatus.IN_PROGRESS.value]
    elif selected_category == "Assessment & Offers":
        status_in = [ApplicationStatus.ASSESSMENT.value, ApplicationStatus.INTERVIEW.value, ApplicationStatus.OFFER.value]
    elif selected_category == "Concluded":
        status_in = [ApplicationStatus.REJECTED.value, ApplicationStatus.WITHDRAWN.value, ApplicationStatus.CLOSED.value]

    employment_type = selected_emp if selected_emp != "All Types" else None

    return {
        "view_mode": view_mode,
        "search_term": search_term.strip() if search_term else None,
        "status_in": status_in,
        "employment_type": employment_type,
        "sort_by": sort_by,
        "include_archived": include_archived,
    }


# =============================================================================
# 4. LIFECYCLE TIMELINE VIEW (Strictly Read-Only)
# =============================================================================

def render_lifecycle_timeline_view(
    service: DashboardService,
    session_id: str,
    app_id: int,
    user_id: int,
) -> None:
    """Renders the chronological lifecycle audit trail with cryptographic hash-chain badge."""
    try:
        timeline_info = service.get_application_timeline(
            application_id=app_id,
            session_id=session_id,
        )
    except (DatabaseError, KeyError, ValueError) as exc:
        st.error(f"Cannot load application timeline: {exc}")
        return

    chain_valid = timeline_info.get("chain_valid", False)
    verification_message = timeline_info.get("verification_message", "")

    if chain_valid:
        st.success(f"🛡️ {verification_message}")
    else:
        st.error(f"🚨 {verification_message}")

    events = timeline_info.get("events", [])
    if not events:
        st.caption("No lifecycle events recorded for this application.")
        return

    st.markdown("##### Chronological Audit Event Chain")
    for event in events:
        payload = {}
        if getattr(event, "event_payload_json", None):
            try:
                payload = json.loads(event.event_payload_json) if isinstance(event.event_payload_json, str) else event.event_payload_json
            except (json.JSONDecodeError, ValueError, TypeError):
                payload = {}
        elif getattr(event, "event_payload", None):
            payload = event.event_payload or {}
        old_s = payload.get("old_status")
        new_s = payload.get("new_status")
        status_flow = f" (`{old_s}` ➔ `{new_s}`)" if old_s and new_s else ""

        col_time, col_desc = st.columns([2, 5])
        with col_time:
            st.caption(f"#{event.sequence_no} • `{event.created_at or 'Timestamp N/A'}`")
        with col_desc:
            st.markdown(f"**{event.event_type}**{status_flow}")
            if event.event_type == "EXTERNAL_APPLICATION_URL_OPENED":
                st.caption("ℹ️ *Employer portal destination validated; navigation requested, visit not verified*")
            st.caption(f"**Actor:** `{event.actor_type}` ({event.actor_identifier})")
            # Safe payload details
            safe_notes = payload.get("note") or payload.get("notes") or payload.get("reason") or payload.get("reopen_rationale")
            if safe_notes:
                st.caption(f"📝 *Notes:* {safe_notes}")
            if payload.get("opened_url"):
                st.caption(f"🌐 *Employer portal destination validated; navigation requested, visit not verified:* `{payload['opened_url']}`")
            if payload.get("channel"):
                st.caption(f"📬 *Submission Channel:* `{payload['channel']}` | *Ref:* `{payload.get('reference') or 'N/A'}`")


# =============================================================================
# 5. PREPARED PACKET REVIEW & VERIFIED DOCUMENT DOWNLOADS
# =============================================================================

def render_prepared_packets_view(
    service: DashboardService,
    session_id: str,
    app_id: int,
    user_id: int,
) -> None:
    """Renders historical packet revisions, approval provenance, and verified PDF/DOCX downloads."""
    try:
        packets = service.list_candidate_prepared_packets(
            application_id=app_id,
            session_id=session_id,
        )
    except (DatabaseError, KeyError, ValueError) as exc:
        st.error(f"Cannot load prepared packets: {exc}")
        return

    if not packets:
        st.info("No prepared packet revisions exist for this application.")
        st.caption("You can prepare and compile tailored materials in the **Application Preparer** workspace.")
        return

    st.markdown(f"##### Prepared Application Revisions ({len(packets)} Revisions)")

    for pkt_meta in packets:
        pkt_id = pkt_meta["packet_id"]
        v_num = pkt_meta["version_num"]
        is_active = pkt_meta["is_active_revision"]
        is_legacy = pkt_meta.get("is_legacy", False)
        created_at = pkt_meta.get("created_at", "N/A")

        status_tag = "ACTIVE REVISION" if is_active else "HISTORICAL REVISION"
        legacy_tag = " • [LEGACY]" if is_legacy else ""
        header = f"Revision #{v_num} — {created_at} [{status_tag}]{legacy_tag}"

        with st.expander(header, expanded=is_active):
            # Detailed packet retrieval
            try:
                pkt_detail = service.get_candidate_prepared_packet(
                    application_id=app_id,
                    packet_id=pkt_id,
                    session_id=session_id,
                )
            except (DatabaseError, KeyError, ValueError) as exc:
                st.error(f"Error reading packet #{pkt_id}: {exc}")
                continue

            # Integrity Indicator
            integrity_valid = pkt_detail.get("integrity_valid", False)
            ver_msg = pkt_detail.get("verification_message", "")
            if integrity_valid:
                st.success(f"🛡️ {ver_msg}")
            else:
                st.warning(f"⚠️ {ver_msg}")

            # Approval Provenance
            appr = pkt_detail.get("approval", {})
            if appr.get("is_approved"):
                st.markdown(
                    f"✅ **Human Approved** by `{appr.get('approver_name')}` at `{appr.get('approved_at')}` "
                    f"| Action Ticket Consumed: `{'Yes' if appr.get('is_consumed') else 'No'}`"
                )
            else:
                st.markdown("⏳ **Awaiting Human Approval** in Application Preparer workspace.")

            # Packet Hash
            hash_val = pkt_detail.get("packet_version_hash", "N/A")
            st.caption(f"**Canonical Version Hash:** `{hash_val}`")

            # Material Previews (if integrity valid)
            if integrity_valid:
                resume_data = pkt_detail.get("tailored_resume", {})
                cover_data = pkt_detail.get("cover_letter", {})
                qa_data = pkt_detail.get("screening_questions", [])
                manifest_data = pkt_detail.get("attachments_manifest", [])

                tab_res, tab_cov, tab_qa, tab_att = st.tabs([
                    "📄 Tailored Resume",
                    "✍️ Cover Letter",
                    "💬 Screening QA",
                    "📎 Attachments",
                ])

                with tab_res:
                    if resume_data:
                        st.markdown(f"**Candidate:** {resume_data.get('name', 'Candidate')}")
                        if resume_data.get("summary"):
                            st.markdown(f"*{resume_data['summary']}*")
                        skills = resume_data.get("technical_skills", [])
                        if skills:
                            st.caption(f"**Skills:** {', '.join(skills)}")
                    else:
                        st.caption("No tailored resume content recorded in snapshot.")

                with tab_cov:
                    if cover_data:
                        tone = cover_data.get("tone", "Professional")
                        st.caption(f"**Tone:** {tone}")
                        st.text_area(
                            "Cover Letter Body",
                            value=cover_data.get("letter_text", ""),
                            height=180,
                            disabled=True,
                            key=f"cl_view_{user_id}_{pkt_id}",
                        )
                    else:
                        st.caption("No cover letter content recorded in snapshot.")

                with tab_qa:
                    if qa_data:
                        for idx, q in enumerate(qa_data, start=1):
                            q_text = q.get("question") or q.get("question_text", "Question")
                            a_text = q.get("answer") or q.get("answer_text", "Answer")
                            st.markdown(f"**Q{idx}:** {q_text}")
                            st.caption(f"**A:** {a_text}")
                    else:
                        st.caption("No screening question responses in snapshot.")

                with tab_att:
                    if manifest_data:
                        st.markdown("**Sanitized Attachments Manifest:**")
                        for att in manifest_data:
                            size_display = att.get("size_kb") or f"{att.get('size_bytes')} bytes"
                            st.caption(
                                f"• `{att.get('artifact_type')}` — **{att.get('filename')}** "
                                f"({att.get('format')}, {size_display})"
                            )
                    else:
                        st.caption("No attachment entries recorded in manifest.")

            # Document Downloads (Secure, Verified Bytes Only)
            st.markdown("###### Download Verified Packet Documents")
            docs_avail = pkt_detail.get("documents_available", {})

            doc_download_types = [
                ("tailored_resume_pdf", "📄 Tailored Resume (PDF)"),
                ("tailored_resume_docx", "📄 Tailored Resume (DOCX)"),
                ("cover_letter_pdf", "✍️ Cover Letter (PDF)"),
                ("cover_letter_docx", "✍️ Cover Letter (DOCX)"),
                ("screening_qa_pdf", "💬 Screening QA (PDF)"),
                ("screening_qa_docx", "💬 Screening QA (DOCX)"),
                ("consolidated_packet_pdf", "📦 Consolidated Packet (PDF)"),
                ("consolidated_packet_docx", "📦 Consolidated Packet (DOCX)"),
            ]

            dl_cols = st.columns(4)
            col_idx = 0
            has_downloads = False

            for doc_type, label in doc_download_types:
                if docs_avail.get(doc_type):
                    has_downloads = True
                    with dl_cols[col_idx % 4]:
                        try:
                            file_bytes, safe_filename, mime_type = service.get_candidate_packet_document(
                                application_id=app_id,
                                packet_id=pkt_id,
                                document_type=doc_type,
                                session_id=session_id,
                            )
                            st.download_button(
                                label=label,
                                data=file_bytes,
                                file_name=safe_filename,
                                mime=mime_type,
                                key=f"dl_btn_{user_id}_{pkt_id}_{doc_type}",
                            )
                        except (DatabaseError, OSError, ValueError) as exc:
                            st.caption(f"{label} unavailable: {exc}")
                    col_idx += 1

            if not has_downloads:
                st.caption("No compiled PDF or DOCX documents are available for download in this revision.")


# =============================================================================
# 6. EXTERNAL EMPLOYER NAVIGATION
# =============================================================================

def render_external_navigation_action(
    service: DashboardService,
    session_id: str,
    app: Application,
    user_id: int,
) -> None:
    """Renders the validated external employer portal URL preparation action."""
    st.markdown("##### 🌐 Employer Career Portal")

    if not app.external_application_url:
        st.caption("No external application URL has been configured for this opportunity.")
        return

    st.caption(f"**Configured Destination:** `{app.external_application_url}`")
    st.caption(
        "ℹ️ *Note: Validating destination safety and logging navigation preparation records that you requested "
        "the portal link, but does not prove or verify that you visited, logged into, or submitted via the external employer portal.*"
    )
    session_url_key = f"validated_url_{user_id}_{app.id}"

    col_btn, col_link = st.columns([2, 3])
    with col_btn:
        if st.button("Validate and Prepare Employer Link", key=f"prep_url_btn_{user_id}_{app.id}"):
            try:
                validated_url = service.log_external_application_url_opened(
                    application_id=app.id,
                    session_id=session_id,
                )
                st.session_state[session_url_key] = validated_url
                st.success("Employer portal destination validated & navigation preparation logged. (Note: External portal visit cannot be independently verified.)")
            except (DatabaseError, ValueError) as exc:
                st.error(f"Cannot verify destination URL: {exc}")

    with col_link:
        val_url = st.session_state.get(session_url_key)
        if val_url:
            st.warning("⚠️ You are navigating to an external employer website. The assistant never automates portal actions.")
            st.link_button("🚀 Proceed to Employer Portal", url=val_url)


# =============================================================================
# 7. MANUAL SUBMISSION CONFIRMATION DIALOG / SECTION
# =============================================================================

def render_manual_submission_section(
    service: DashboardService,
    session_id: str,
    app: Application,
    user_id: int,
) -> None:
    """Renders the strict cryptographic manual submission confirmation workflow for APPROVED applications."""
    try:
        norm_status = ApplicationStateMachine.normalize_status(app.status)
    except (KeyError, ValueError, AttributeError):
        norm_status = None

    if norm_status != ApplicationStatus.APPROVED:
        return

    st.markdown("---")
    st.markdown("### 🚀 Confirm Manual Job Submission")
    st.warning(
        "⚠️ **Human-in-the-Loop Governance Notice:**\n\n"
        "The assistant **never** submits job applications automatically. "
        "Confirm only after you have personally completed and submitted your application "
        "through the employer's official website."
    )

    with st.container():
        confirm_checked = st.checkbox(
            "I confirm that I have personally completed and submitted this job application on the official employer website.",
            key=f"sub_confirm_chk_{user_id}_{app.id}",
        )

        col_chan, col_ref = st.columns(2)
        with col_chan:
            channels = SubmissionChannel.list()
            channel = st.selectbox(
                "Submission Channel",
                options=channels,
                index=0,
                key=f"sub_channel_sel_{user_id}_{app.id}",
            )
        with col_ref:
            conf_ref = st.text_input(
                "Confirmation Reference / Application ID (Optional)",
                placeholder="e.g. APP-2026-98124",
                key=f"sub_ref_input_{user_id}_{app.id}",
            )

        notes_input = st.text_area(
            "Candidate Submission Notes (Optional)",
            placeholder="Notes regarding documents submitted, recruiter contacts, or referral details...",
            key=f"sub_notes_input_{user_id}_{app.id}",
            height=70,
        )

        proof_file = st.file_uploader(
            "Upload Optional Submission Confirmation Evidence",
            type=["pdf", "png", "jpg", "jpeg"],
            help="Optional: Upload an employer confirmation email/PDF or receipt screenshot (PDF, PNG, JPEG up to 10 MB).",
            key=f"sub_proof_file_{user_id}_{app.id}",
        )

        if st.button("Confirm Submission & Transition to SUBMITTED", type="primary", key=f"sub_submit_btn_{user_id}_{app.id}"):
            if not confirm_checked:
                st.error("You must explicitly check the confirmation checkbox to authorize manual submission.")
                return

            try:
                # 1. Fetch active prepared packet for version hash
                active_packet = service.db.get_active_prepared_packet(
                    application_id=app.id,
                    user_id=user_id,
                )
                if not active_packet:
                    st.error("No active prepared packet found for this application. Prepare and approve materials first.")
                    return

                # 2. Issue fresh action ticket bound to application and active packet hash
                ticket = service.issue_manual_submission_ticket(
                    session_id=session_id,
                    application_id=app.id,
                    packet_hash=active_packet.packet_version_hash,
                )

                # Extract optional uploaded proof bytes safely
                proof_bytes = None
                proof_filename = None
                if proof_file is not None:
                    raw_val = getattr(proof_file, "getvalue", None)
                    if callable(raw_val):
                        val = raw_val()
                        if isinstance(val, (bytes, bytearray)) and len(val) > 0:
                            proof_bytes = bytes(val)
                            proof_filename = getattr(proof_file, "name", "proof.pdf")

                # 3. Atomically record submission confirmation
                service.record_candidate_manual_submission(
                    application_id=app.id,
                    session_id=session_id,
                    submission_ticket=ticket,
                    candidate_confirmed=True,
                    submission_channel=channel,
                    submission_timestamp=datetime.now(UTC).isoformat(),
                    confirmation_reference=conf_ref.strip() if conf_ref else None,
                    candidate_notes=notes_input.strip() if notes_input else None,
                    proof_bytes=proof_bytes,
                    proof_filename=proof_filename,
                )

                if proof_bytes is not None:
                    st.success("Manual submission successfully confirmed with evidence attached! Application status updated to SUBMITTED.")
                else:
                    st.success("Manual submission successfully confirmed! Application status updated to SUBMITTED.")
                st.rerun()

            except (DatabaseError, ValueError) as exc:
                st.error(f"Manual submission confirmation failed: {exc}")


# =============================================================================
# 8. LIFECYCLE STATUS TRANSITIONS
# =============================================================================

def render_lifecycle_status_actions(
    service: DashboardService,
    session_id: str,
    app: Application,
    user_id: int,
) -> None:
    """Renders generic allowed lifecycle transitions, strictly excluding gate-protected states."""
    st.markdown("##### 🔄 Lifecycle Status Transition")

    try:
        allowed_targets = ApplicationStateMachine.get_allowed_transitions(
            current_status=app.status,
            include_gate_protected=False,  # Excludes APPROVED and SUBMITTED
        )
    except (DatabaseError, KeyError, ValueError) as exc:
        st.error(f"Cannot resolve state transitions: {exc}")
        return

    if not allowed_targets:
        st.caption(f"No generic status transitions available from current status `{app.status}`.")
        return

    # Check if application is currently in a terminal status
    try:
        is_terminal = ApplicationStateMachine.normalize_status(app.status) in ApplicationStateMachine.TERMINAL_STATUSES
    except (KeyError, ValueError, AttributeError):
        is_terminal = False

    col_target, col_notes, col_btn = st.columns([2, 3, 2])

    with col_target:
        target_status = st.selectbox(
            "New Status",
            options=allowed_targets,
            key=f"trans_target_sel_{user_id}_{app.id}",
        )

    # Reopening check: terminal -> IN_PROGRESS
    is_reopening = is_terminal and target_status == ApplicationStatus.IN_PROGRESS.value

    with col_notes:
        if is_reopening:
            reopen_rationale = st.text_input(
                "Reopening Rationale (Mandatory)",
                placeholder="Required rationale for reopening concluded application...",
                key=f"reopen_rat_{user_id}_{app.id}",
            )
            trans_notes = None
        else:
            reopen_rationale = None
            trans_notes = st.text_input(
                "Transition Notes (Optional)",
                placeholder="Optional progress or interview notes...",
                key=f"trans_notes_{user_id}_{app.id}",
            )

    with col_btn:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button(f"Move to {target_status}", key=f"trans_exec_btn_{user_id}_{app.id}"):
            if is_reopening and (not reopen_rationale or not reopen_rationale.strip()):
                st.error("Reopening an application from a concluded status requires a mandatory candidate rationale.")
                return

            try:
                service.transition_application_status(
                    application_id=app.id,
                    session_id=session_id,
                    new_status=target_status,
                    expected_current_status=app.status,
                    transition_metadata={"notes": trans_notes.strip()} if trans_notes and trans_notes.strip() else None,
                    reopen_rationale=reopen_rationale.strip() if reopen_rationale else None,
                )
                st.success(f"Application status updated to {target_status}.")
                st.rerun()
            except (InvalidStatusTransitionError, SecurityAuthorizationError, ValidationError) as exc:
                st.error(f"Transition rejected: {exc}")
            except (DatabaseError, ValueError) as exc:
                st.error(f"Error transitioning status: {exc}")


# =============================================================================
# 9. FOLLOW-UP REMINDER MANAGER
# =============================================================================

def render_follow_up_manager(
    service: DashboardService,
    session_id: str,
    app: Application,
    user_id: int,
    include_archived: bool,
) -> None:
    """Renders scheduled reminders list, completion, deletion, algorithmic recommendations,
    and draft template generation.
    """
    st.markdown("##### 📅 Follow-Up Reminders")

    try:
        app_follow_ups = service.list_application_follow_ups(
            session_id=session_id,
            application_id=app.id,
            include_archived=include_archived,
        )
    except (DatabaseError, KeyError, ValueError) as exc:
        st.error(f"Cannot load reminders: {exc}")
        app_follow_ups = []

    # Display existing reminders
    if app_follow_ups:
        for f in app_follow_ups:
            status_text = "✅ Completed" if f.is_completed else "⏳ Pending"
            with st.container():
                col_f_info, col_f_actions = st.columns([4, 2])
                with col_f_info:
                    st.markdown(f"**{f.follow_up_type}** on `{f.follow_up_date}` • *{status_text}*")
                    st.caption(f"**Task:** {f.description}")
                    if f.outcome_notes:
                        st.caption(f"📝 *Outcome:* {f.outcome_notes}")
                with col_f_actions:
                    if not f.is_completed:
                        with st.popover("Complete", key=f"fup_comp_pop_{user_id}_{f.id}"):
                            outcome = st.text_input("Outcome Notes", key=f"fup_notes_{user_id}_{f.id}")
                            if st.button("Mark Complete", key=f"fup_comp_btn_{user_id}_{f.id}"):
                                try:
                                    service.complete_application_follow_up(
                                        session_id=session_id,
                                        follow_up_id=f.id,
                                        outcome_notes=outcome.strip() if outcome else None,
                                    )
                                    st.success("Reminder completed.")
                                    st.rerun()
                                except (DatabaseError, ValidationError, SecurityAuthorizationError) as exc:
                                    st.error(f"Error: {exc}")

                    with st.popover("Delete", key=f"fup_del_pop_{user_id}_{f.id}"):
                        st.warning("Confirm deleting this reminder?")
                        if st.button("Confirm Delete", key=f"fup_del_btn_{user_id}_{f.id}"):
                            try:
                                deleted = service.delete_application_follow_up(
                                    session_id=session_id,
                                    follow_up_id=f.id,
                                )
                                if deleted:
                                    st.success("Reminder deleted.")
                                    st.rerun()
                                else:
                                    st.error("Reminder could not be found or has already been deleted.")
                            except (DatabaseError, ValidationError, SecurityAuthorizationError) as exc:
                                st.error(f"Error deleting: {exc}")
                st.divider()
    else:
        st.caption("No follow-up reminders scheduled for this application.")

    # Guard: Archived applications show historical reminders above, but disable active intelligence and scheduling
    if bool(getattr(app, "is_archived", 0)):
        st.info("📦 This application is archived. Follow-up recommendations, scheduling, and draft generation are disabled.")
        return

    # -------------------------------------------------------------------------
    # Follow-Up Intelligence & Algorithmic Recommendation
    # -------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("###### 💡 Follow-Up Intelligence")

    extra_context: dict[str, Any] = {}

    # Candidate context inputs for status-specific recommendations
    if app.status == ApplicationStatus.INTERVIEW.value:
        with st.container():
            st.caption("ℹ️ *To receive a 24-hour thank-you note recommendation, provide the date your interview took place.*")
            provide_int_date = st.checkbox(
                "Provide interview date for recommendation",
                key=f"rec_int_chk_{user_id}_{app.id}",
            )
            if provide_int_date:
                int_date_input = st.date_input(
                    "Interview Date",
                    key=f"rec_int_date_{user_id}_{app.id}",
                )
                extra_context["interview_date"] = int_date_input.isoformat()
                extra_context["interview_date_source"] = "candidate_provided"
                st.caption("🔒 *Date is labeled as candidate-provided and unverified; it is not persisted to the application record.*")
    elif app.status == ApplicationStatus.ASSESSMENT.value:
        with st.container():
            st.caption("ℹ️ *To receive an assessment status inquiry recommendation, provide your assessment completion date.*")
            provide_assess_date = st.checkbox(
                "Provide assessment completion date",
                key=f"rec_assess_chk_{user_id}_{app.id}",
            )
            if provide_assess_date:
                assess_date_input = st.date_input(
                    "Assessment Date",
                    key=f"rec_assess_date_{user_id}_{app.id}",
                )
                extra_context["assessment_date"] = assess_date_input.isoformat()

    try:
        rec_res = service.recommend_application_follow_up(
            application_id=app.id,
            session_id=session_id,
            extra_context=extra_context if extra_context else None,
        )
    except (DatabaseError, ValidationError, SecurityAuthorizationError) as exc:
        st.caption(f"Recommendation unavailable: {exc}")
        rec_res = None

    if rec_res:
        if rec_res.get("has_recommendation"):
            rec_type = rec_res.get("recommendation_type") or "STATUS_INQUIRY"
            rec_date_str = rec_res.get("recommended_date") or ""
            rec_rationale = rec_res.get("rationale") or ""
            rec_desc = rec_res.get("default_description") or ""

            st.info(f"📋 **Recommended Action:** `{rec_type}` • **Proposed Date:** `{rec_date_str}`\n\n**Rationale:** {rec_rationale}")
            st.caption("💡 *This is an algorithmic recommendation based on application status. It has NOT been scheduled. Review or edit details below before scheduling.*")

            with st.expander("🗓️ Review & Schedule Proposed Reminder", expanded=False):
                try:
                    default_d = datetime.strptime(rec_date_str, "%Y-%m-%d").date() if rec_date_str else datetime.now(UTC).date()
                except Exception:
                    default_d = datetime.now(UTC).date()

                col_rec_d, col_rec_t = st.columns(2)
                with col_rec_d:
                    sched_date = st.date_input(
                        "Reminder Date",
                        value=default_d,
                        key=f"rec_sched_date_{user_id}_{app.id}",
                    )
                with col_rec_t:
                    type_opts = FollowUpType.list()
                    type_idx = type_opts.index(rec_type) if rec_type in type_opts else 0
                    sched_type = st.selectbox(
                        "Reminder Type",
                        options=type_opts,
                        index=type_idx,
                        key=f"rec_sched_type_{user_id}_{app.id}",
                    )
                sched_desc = st.text_input(
                    "Task Description",
                    value=rec_desc,
                    key=f"rec_sched_desc_{user_id}_{app.id}",
                )

                if st.button("Schedule This Reminder", key=f"rec_sched_btn_{user_id}_{app.id}"):
                    if not sched_desc or not sched_desc.strip():
                        st.error("Please enter a description for the reminder.")
                    else:
                        try:
                            service.create_application_follow_up(
                                session_id=session_id,
                                application_id=app.id,
                                follow_up_date=sched_date.isoformat(),
                                follow_up_type=sched_type,
                                description=sched_desc.strip(),
                            )
                            st.success("Follow-up reminder scheduled successfully.")
                            st.rerun()
                        except (DatabaseError, ValidationError, SecurityAuthorizationError) as exc:
                            st.error(f"Cannot schedule reminder: {exc}")
        else:
            rec_rationale = rec_res.get("rationale") or "No automatic follow-up recommendation configured for this status."
            st.caption(f"ℹ️ {rec_rationale}")

    # -------------------------------------------------------------------------
    # Message Draft Template Generator
    # -------------------------------------------------------------------------
    st.markdown("---")
    with st.expander("✉️ Generate Follow-Up Message Draft", expanded=False):
        st.caption("Draft a professional, zero-hallucination message for manual candidate review and dispatch.")
        st.warning(
            "⚠️ **Candidate-Controlled Drafting:** Generating a draft does NOT send an email or contact recruiters. "
            "All messages require manual review and sending by you."
        )

        sel_template_type = st.selectbox(
            "Template Type",
            options=list(SUPPORTED_TEMPLATE_TYPES),
            key=f"tpl_type_{user_id}_{app.id}",
        )

        col_rec, col_int = st.columns(2)
        with col_rec:
            rec_name_input = st.text_input(
                "Recruiter Name (Optional)",
                placeholder="e.g. Jane Doe",
                key=f"tpl_rec_name_{user_id}_{app.id}",
            )
        with col_int:
            int_name_input = st.text_input(
                "Interviewer Name (Optional)",
                placeholder="e.g. Dr. Alex Smith",
                key=f"tpl_int_name_{user_id}_{app.id}",
            )

        tpl_ctx: dict[str, Any] = {}
        if rec_name_input and rec_name_input.strip():
            tpl_ctx["recruiter_name"] = rec_name_input.strip()
        if int_name_input and int_name_input.strip():
            tpl_ctx["interviewer_name"] = int_name_input.strip()

        if sel_template_type == "THANK_YOU_NOTE":
            include_int_date = st.checkbox(
                "Include specific interview date in thank-you note",
                key=f"tpl_include_date_{user_id}_{app.id}",
            )
            if include_int_date:
                int_date_val = st.date_input(
                    "Interview Date",
                    key=f"tpl_int_date_{user_id}_{app.id}",
                )
                tpl_ctx["interview_date"] = int_date_val.isoformat()
                tpl_ctx["interview_date_source"] = "candidate_provided"

        if st.button("Generate Draft", key=f"gen_tpl_btn_{user_id}_{app.id}"):
            try:
                draft_res = service.generate_follow_up_template(
                    application_id=app.id,
                    session_id=session_id,
                    follow_up_type=sel_template_type,
                    extra_context=tpl_ctx if tpl_ctx else None,
                )
                st.session_state[f"generated_draft_{user_id}_{app.id}"] = draft_res
                st.success("Draft generated successfully. Review and edit below before manual sending.")
            except (DatabaseError, ValidationError, SecurityAuthorizationError) as exc:
                st.error(f"Cannot generate template: {exc}")

        draft_data = st.session_state.get(f"generated_draft_{user_id}_{app.id}")
        if draft_data:
            st.markdown("###### 📝 Generated Draft (Editable)")
            st.text_input(
                "Subject",
                value=draft_data.get("subject", ""),
                key=f"draft_subj_{user_id}_{app.id}",
            )
            st.text_area(
                "Body",
                value=draft_data.get("body", ""),
                height=220,
                key=f"draft_body_{user_id}_{app.id}",
            )

            meta = draft_data.get("context_metadata", {})
            cand_name_meta = meta.get("candidate_name", "[CANDIDATE NAME]")
            rec_src_meta = meta.get("recruiter_name_source", "placeholder")
            int_src_meta = meta.get("interview_date_source", "unavailable")
            st.caption(
                f"**Candidate:** `{cand_name_meta}` • **Recruiter source:** `{rec_src_meta}` • **Interview date source:** `{int_src_meta}`"
            )
            st.info("📋 Copy the subject and body above to send manually through your preferred email client or portal.")

    # -------------------------------------------------------------------------
    # Manual Custom Reminder Scheduling
    # -------------------------------------------------------------------------
    st.markdown("---")
    with st.expander("➕ Schedule Custom Follow-Up Reminder", expanded=False):
        col_d, col_t = st.columns(2)
        with col_d:
            f_date = st.date_input("Reminder Date", key=f"new_fup_date_{user_id}_{app.id}")
        with col_t:
            f_type = st.selectbox(
                "Reminder Type",
                options=FollowUpType.list(),
                key=f"new_fup_type_{user_id}_{app.id}",
            )
        f_desc = st.text_input(
            "Task Description",
            placeholder="e.g. Follow up on technical assessment status...",
            key=f"new_fup_desc_{user_id}_{app.id}",
        )
        if st.button("Schedule Reminder", key=f"new_fup_btn_{user_id}_{app.id}"):
            if not f_desc or not f_desc.strip():
                st.error("Please enter a description for the reminder.")
            else:
                try:
                    service.create_application_follow_up(
                        session_id=session_id,
                        application_id=app.id,
                        follow_up_date=f_date.isoformat(),
                        follow_up_type=f_type,
                        description=f_desc.strip(),
                    )
                    st.success("Follow-up reminder scheduled successfully.")
                    st.rerun()
                except (DatabaseError, ValidationError, SecurityAuthorizationError) as exc:
                    st.error(f"Cannot schedule reminder: {exc}")


# =============================================================================
# 10. ARCHIVE APPLICATION ACTION
# =============================================================================

def render_archive_action(
    service: DashboardService,
    session_id: str,
    app: Application,
    user_id: int,
) -> None:
    """Renders the safe soft-archive application action."""
    if app.is_archived:
        st.info("📦 This application is currently archived. It is excluded from active pipeline counts.")
        return

    with st.expander("📦 Archive Application", expanded=False):
        st.caption("Archiving hides the application from active dashboard metrics and active pipeline views.")
        reason = st.text_input(
            "Archive Reason (Optional)",
            placeholder="e.g. Opportunity cancelled, position filled...",
            key=f"arch_reason_{user_id}_{app.id}",
        )
        confirm_archive = st.checkbox(
            "I confirm that I want to archive this application.",
            key=f"arch_confirm_{user_id}_{app.id}",
        )
        if st.button("Archive Application", key=f"arch_btn_{user_id}_{app.id}"):
            if not confirm_archive:
                st.error("Please check the confirmation box to archive this application.")
            else:
                try:
                    service.archive_candidate_application(
                        application_id=app.id,
                        session_id=session_id,
                        archive_reason=reason.strip() if reason else None,
                    )
                    st.success("Application successfully archived.")
                    st.rerun()
                except (DatabaseError, ValueError) as exc:
                    st.error(f"Error archiving application: {exc}")


# =============================================================================
# 11. SUBMISSION CONFIRMATION & EVIDENCE DETAILS
# =============================================================================

def render_submission_confirmation_details(
    service: DashboardService,
    session_id: str,
    app: Application,
    user_id: int,
) -> None:
    """Renders candidate-facing submission confirmation metadata and verified proof download controls."""
    try:
        conf_meta = service.get_candidate_submission_confirmation(
            application_id=app.id,
            session_id=session_id,
        )
    except (DatabaseError, KeyError, ValueError, AttributeError) as exc:
        st.error(f"Unable to load submission confirmation: {exc}")
        return

    if not conf_meta:
        return

    st.markdown("---")
    st.markdown("##### 📄 Submission Confirmation & Evidence")
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown(f"**Submitted Channel:** `{conf_meta['submission_channel']}`")
        st.markdown(f"**Submission Timestamp:** `{conf_meta['submission_timestamp']}`")
    with col_b:
        conf_ref_display = conf_meta.get("confirmation_reference") or "None recorded"
        st.markdown(f"**Confirmation Reference:** `{conf_ref_display}`")
        if conf_meta.get("candidate_notes"):
            st.markdown(f"**Notes:** {conf_meta['candidate_notes']}")

    if conf_meta.get("has_proof"):
        st.markdown(f"**Confirmation Evidence:** `{conf_meta['safe_display_name']}` *(Integrity Verified)*")
        try:
            file_bytes, safe_filename, mime_type = service.get_candidate_submission_confirmation_proof(
                application_id=app.id,
                session_id=session_id,
            )
            st.download_button(
                label=f"⬇️ Download Submission Evidence ({safe_filename})",
                data=file_bytes,
                file_name=safe_filename,
                mime=mime_type,
                key=f"dl_proof_{user_id}_{app.id}_{conf_meta['confirmation_id']}",
            )
        except (DatabaseError, OSError, ValueError, KeyError) as exc:
            st.error(f"Unable to load verified confirmation evidence: {exc}")
    else:
        st.info("No confirmation evidence document attached.")
        with st.expander("📎 Attach Confirmation Evidence", expanded=False):
            attach_file = st.file_uploader(
                "Select confirmation proof (PDF, PNG, JPEG up to 10 MB)",
                type=["pdf", "png", "jpg", "jpeg"],
                key=f"attach_proof_{user_id}_{app.id}",
            )
            if st.button("Upload & Attach Proof", key=f"btn_attach_proof_{user_id}_{app.id}"):
                if attach_file is not None:
                    raw_val = getattr(attach_file, "getvalue", None)
                    raw_bytes = raw_val() if callable(raw_val) else None
                    if isinstance(raw_bytes, (bytes, bytearray)) and len(raw_bytes) > 0:
                        try:
                            service.attach_submission_confirmation_proof(
                                application_id=app.id,
                                session_id=session_id,
                                file_bytes=bytes(raw_bytes),
                                original_filename=getattr(attach_file, "name", "proof.pdf"),
                            )
                            st.success("Evidence document successfully verified and attached!")
                            st.rerun()
                        except (DatabaseError, ValueError, OSError) as exc:
                            st.error(f"Failed to attach evidence: {exc}")
                    else:
                        st.warning("Selected file is empty.")
                else:
                    st.warning("Please select a file to upload.")


# =============================================================================
# 12. APPLICATION DETAIL CARD (List View)
# =============================================================================

def render_application_card(
    app: Application,
    service: DashboardService,
    session_id: str,
    user_id: int,
    include_archived: bool,
) -> None:
    """Renders a comprehensive, expandable application card with detail tabs."""
    # Match Evaluation Detail
    match_detail = service.get_candidate_application_match_detail(
        application_id=app.id,
        session_id=session_id,
    )

    if match_detail and hasattr(match_detail, "overall_score"):
        score_badge = f"Match: {match_detail.overall_score:.1f} ({getattr(match_detail, 'classification', 'N/A')})"
    else:
        score_badge = "Match Evaluation Unavailable"

    status_tag = format_status_badge(app.status)
    archived_tag = " • [ARCHIVED]" if app.is_archived else ""
    card_title = f"{status_tag} **{app.job_title}** at **{app.company_name}** ({score_badge}){archived_tag}"

    with st.expander(card_title, expanded=False):
        # Summary Row
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.caption(f"📍 **Location:** {app.location or 'Not specified'}")
        with col2:
            st.caption(f"💼 **Type:** {app.employment_type or 'Not specified'}")
        with col3:
            st.caption(f"💰 **Salary:** {app.salary_range or 'Not specified'}")
        with col4:
            st.caption(f"⏳ **Deadline:** {app.application_deadline or 'Not specified'}")

        # Six Detail Tabs
        tab_overview, tab_match, tab_timeline, tab_packets, tab_transitions, tab_follow_ups = st.tabs([
            "📋 Overview",
            "🎯 Match Evaluation",
            "🛡️ Lifecycle Timeline",
            "📜 Prepared Packets",
            "⚡ Actions & Transitions",
            "📅 Follow-ups & Archive",
        ])

        with tab_overview:
            st.markdown("##### Application Details")
            st.markdown(f"**Company:** {app.company_name} | **Role:** {app.job_title}")
            st.markdown(f"**Current Lifecycle Status:** `{app.status}`")
            if app.target_role:
                st.caption(f"**Target Role Focus:** {app.target_role}")
            if app.notes:
                st.markdown(f"**Candidate Notes:** {app.notes}")

            st.caption(
                f"**Created:** `{app.created_at or 'N/A'}` | "
                f"**Updated:** `{app.updated_at or 'N/A'}` | "
                f"**Source:** `{app.application_source}`"
            )
            if app.job_description_id:
                st.caption(f"**Linked Job Description ID:** #{app.job_description_id}")
            if app.resume_id:
                st.caption(f"**Linked Resume ID:** #{app.resume_id}")

            render_submission_confirmation_details(service, session_id, app, user_id)

        with tab_match:
            if match_detail and hasattr(match_detail, "overall_score"):
                st.markdown(f"##### Overall Match Score: **{match_detail.overall_score:.1f} / 100**")
                st.markdown(f"**Classification:** `{getattr(match_detail, 'classification', 'N/A')}`")
                eligibility = getattr(match_detail, "eligibility_status", "UNKNOWN")
                st.markdown(f"**Eligibility:** `{eligibility}`")

                breakdowns = getattr(match_detail, "dimension_scores", {})
                if breakdowns:
                    st.markdown("**Scoring Breakdown:**")
                    b_cols = st.columns(min(len(breakdowns), 6) or 1)
                    for i, (dim, score) in enumerate(breakdowns.items()):
                        with b_cols[i % len(b_cols)]:
                            st.metric(label=dim.replace("_", " ").title(), value=f"{score:.1f}")
                if getattr(match_detail, "match_explanation", None):
                    st.info(match_detail.match_explanation)
            else:
                st.info("Match Evaluation Unavailable")
                st.caption("No linked match evaluation record is bound to this application.")

        with tab_timeline:
            render_lifecycle_timeline_view(service, session_id, app.id, user_id)

        with tab_packets:
            render_prepared_packets_view(service, session_id, app.id, user_id)

        with tab_transitions:
            render_external_navigation_action(service, session_id, app, user_id)
            render_manual_submission_section(service, session_id, app, user_id)
            render_lifecycle_status_actions(service, session_id, app, user_id)

        with tab_follow_ups:
            render_follow_up_manager(service, session_id, app, user_id, include_archived)
            render_archive_action(service, session_id, app, user_id)


# =============================================================================
# 12. FIVE-COLUMN KANBAN BOARD VIEW
# =============================================================================

def render_kanban_board_view(
    applications: list[Application],
    service: DashboardService,
    session_id: str,
    user_id: int,
    include_archived: bool,
) -> None:
    """Renders the exact canonical 5-column Kanban board without drag-and-drop state bypass."""
    st.markdown("### 📊 Application Kanban Board")
    st.caption(f"Showing all {len(applications)} matching applications across five canonical stages. Transitions require authorized workflow actions.")

    # Group applications into the 5 columns
    col_apps: dict[str, list[Application]] = {col["id"]: [] for col in KANBAN_COLUMNS}

    for app in applications:
        try:
            norm = ApplicationStateMachine.normalize_status(app.status).value
        except (KeyError, ValueError, AttributeError):
            norm = app.status

        placed = False
        for col_def in KANBAN_COLUMNS:
            if norm in col_def["statuses"]:
                col_apps[col_def["id"]].append(app)
                placed = True
                break
        if not placed:
            # Default unplaced into preparation
            col_apps["col_prep"].append(app)

    # Render 5 columns
    k_cols = st.columns(5)

    for i, col_def in enumerate(KANBAN_COLUMNS):
        col_id = col_def["id"]
        apps_in_col = col_apps[col_id]

        with k_cols[i]:
            st.markdown(f"#### {col_def['title']}")
            st.caption(f"{len(apps_in_col)} Applications • {col_def['description']}")
            st.divider()

            if not apps_in_col:
                st.caption("No applications in this stage.")
            else:
                for app in apps_in_col:
                    color = STATUS_COLOR_MAP.get(app.status, "#6B7280")
                    if not (isinstance(color, str) and color.startswith("#") and len(color) == 7 and all(c in "0123456789ABCDEFabcdef" for c in color[1:])):
                        color = "#6B7280"
                    border_style = f"border-left: 4px solid {color}; padding: 10px; margin-bottom: 12px; background-color: #FAFAFA; border-radius: 4px;"

                    safe_title = html.escape(str(app.job_title or "Untitled Role"), quote=True)
                    safe_company = html.escape(str(app.company_name or "Unknown Company"), quote=True)
                    safe_status = html.escape(str(app.status or "DRAFT"), quote=True)

                    st.markdown(
                        f"""
                        <div style="{border_style}">
                            <strong>{safe_title}</strong><br>
                            <span style="color: #4B5563;">{safe_company}</span><br>
                            <small>Status: <code>{safe_status}</code></small>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    with st.expander("Manage", expanded=False):
                        st.caption(f"📍 Location: {app.location or 'N/A'}")
                        if app.application_deadline:
                            st.caption(f"⏳ Deadline: {app.application_deadline}")

                        # Manage tabs
                        m_tab_trans, m_tab_pkts, m_tab_time = st.tabs(["⚡ Actions", "📜 Packets", "🛡️ Audit"])
                        with m_tab_trans:
                            render_external_navigation_action(service, session_id, app, user_id)
                            render_manual_submission_section(service, session_id, app, user_id)
                            render_lifecycle_status_actions(service, session_id, app, user_id)
                        with m_tab_pkts:
                            render_prepared_packets_view(service, session_id, app.id, user_id)
                        with m_tab_time:
                            render_lifecycle_timeline_view(service, session_id, app.id, user_id)

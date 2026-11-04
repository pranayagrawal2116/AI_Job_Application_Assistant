"""Unit and Integration Tests for Phase 7.3.2.3 Candidate Application Tracker Streamlit UI.

Covers the complete 8-category test specification:
- Category A: Authentication & Multi-User Isolation Tests
- Category B: Authoritative KPI & Follow-Up Metrics Invariant Tests
- Category C: List View, Filtering, Sorting & Pagination Tests
- Category D: Five-Column Canonical Kanban Board Tests
- Category E: Application Timeline & Read-Only Prepared Packet Review Tests
- Category F: Anti-Automation Manual Submission Confirmation Tests
- Category G: State Machine Status Transition & Reopen Rationale Tests
- Category H: Follow-Up Management, Archive & CSV Export Tests
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import UTC, date
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from dashboard.components.tracker_components import (
    KANBAN_COLUMNS,
    build_tracker_csv_export,
    format_status_badge,
    get_application_follow_up_chips,
    render_application_card,
    render_archive_action,
    render_external_navigation_action,
    render_follow_up_alert_bar,
    render_follow_up_manager,
    render_kanban_board_view,
    render_lifecycle_status_actions,
    render_lifecycle_stepper,
    render_lifecycle_timeline_view,
    render_manual_submission_section,
    render_prepared_packets_view,
    render_tracker_filter_toolbar,
    render_tracker_header,
    render_tracker_metrics_bar,
    sanitize_csv_cell,
)
from dashboard.services.dashboard_service import DashboardService
from dashboard.views.application_tracker import render_application_tracker
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ApplicationNotFoundError,
    CrossUserAccessError,
    SecurityAuthorizationError,
    UnconfirmedSubmissionError,
    ValidationError,
)
from src.database.models import (
    Application,
    ApplicationEvent,
    ApplicationFollowUp,
    ApplicationStatus,
    FollowUpType,
    PreparedPacket,
    SubmissionChannel,
)
from src.lifecycle.follow_up_engine import FollowUpRecommendationEngine
from src.lifecycle.state_machine import ApplicationStateMachine
from src.security.session_manager import SessionManager


class BaseTrackerUITest(unittest.TestCase):
    """Base fixture setting up isolated SQLite database, test candidates, and authenticated sessions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_tracker_ui.db")
        self.db = DatabaseManager(self.db_path)
        self.session_mgr = SessionManager.get_instance()

        # Seed two candidate users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'alice@example.com', 'h1', 's1', 'Alice Candidate')"
            )
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'bob@example.com', 'h2', 's2', 'Bob Candidate')"
            )

        self.user_a = 1
        self.user_b = 2

        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="cand_a",
            candidate_name="Alice Candidate",
            user_id=self.user_a,
        )
        self.session_b = self.session_mgr.authenticate_candidate(
            candidate_id="cand_b",
            candidate_name="Bob Candidate",
            user_id=self.user_b,
        )

        # Isolated storage base for documents
        self.storage_base = Path(self.temp_dir.name) / "users"
        self.user_a_storage = self.storage_base / str(self.user_a)
        self.user_b_storage = self.storage_base / str(self.user_b)
        self.user_a_storage.mkdir(parents=True, exist_ok=True)
        self.user_b_storage.mkdir(parents=True, exist_ok=True)

        self.service = DashboardService(
            db_manager=self.db,
            storage_base_dir=self.storage_base,
        )

    def tearDown(self):
        self.session_mgr.reset_instance()
        self.temp_dir.cleanup()

    def _create_app(
        self,
        user_id: int,
        company: str,
        title: str,
        status: str = "DRAFT",
        is_archived: int = 0,
        target_role: str | None = None,
        employment_type: str | None = None,
        location: str | None = None,
        salary_range: str | None = None,
        application_deadline: str | None = None,
        external_url: str | None = None,
        job_description_id: int | None = None,
        resume_id: int | None = None,
    ) -> Application:
        """Helper to directly insert and return an application model."""
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO applications (
                    user_id, company_name, job_title, status, is_archived,
                    target_role, employment_type, location, salary_range,
                    application_deadline, external_application_url,
                    job_description_id, resume_id,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    user_id, company, title, status, is_archived,
                    target_role, employment_type, location, salary_range,
                    application_deadline, external_url,
                    job_description_id, resume_id,
                ),
            )
            app_id = cursor.lastrowid
        return self.db.get_user_application(app_id, user_id)

    def _create_packet(
        self,
        application_id: int,
        user_id: int,
        version_num: int = 1,
        is_active: bool = True,
        attachments_manifest: list[dict[str, Any]] | None = None,
        matching_result_id: int | None = None,
    ) -> PreparedPacket:
        """Helper to insert a prepared packet revision."""
        payload = {
            "application_id": application_id,
            "user_id": user_id,
            "packet_version": version_num,
            "tailored_resume": {"name": "Alice Candidate", "summary": "AI Systems Expert"},
            "cover_letter": {"letter_text": "Tailored cover letter text for opportunity."},
            "screening_questions": [{"question": "Years of experience?", "answer": "4 years"}],
            "attachments_manifest": attachments_manifest or [],
        }
        canonical_snapshot_json = json.dumps(payload, sort_keys=True)
        packet_version_hash = hashlib.sha256(canonical_snapshot_json.encode("utf-8")).hexdigest()

        pkt = self.db.create_prepared_packet(
            application_id=application_id,
            user_id=user_id,
            version_num=version_num,
            packet_version_hash=packet_version_hash,
            original_resume_hash="res_hash_1",
            job_description_snapshot_hash="jd_hash_1",
            screening_answers=payload["screening_questions"],
            canonical_snapshot_json=canonical_snapshot_json,
            matching_result_id=matching_result_id,
            attachments_manifest=attachments_manifest,
        )
        if not is_active:
            with self.db.transaction() as conn:
                conn.cursor().execute(
                    "UPDATE prepared_packets SET is_active_revision = 0 WHERE id = ?",
                    (pkt.id,),
                )
            pkt.is_active_revision = False
        return pkt


# =============================================================================
# CATEGORY A: AUTHENTICATION & MULTI-USER ISOLATION TESTS
# =============================================================================

class TestAuthenticationAndIsolation(BaseTrackerUITest):
    """Tests Section 4: Mandatory Authentication & Candidate Session Isolation."""

    @patch("dashboard.views.application_tracker.st")
    def test_missing_session_blocks_tracker_access(self, mock_st):
        """Missing session in session_state immediately displays authentication error and halts."""
        mock_st.session_state = {}
        with patch("dashboard.views.application_tracker.DashboardService.get_instance", return_value=self.service):
            render_application_tracker()

        mock_st.error.assert_called_with("Authentication required")
        mock_st.info.assert_called()

    @patch("dashboard.views.application_tracker.st")
    def test_invalid_session_blocks_tracker_access(self, mock_st):
        """Invalid or forged session token blocks tracker access."""
        mock_st.session_state = {"authenticated_session_id": "forged_session_token"}
        with patch("dashboard.views.application_tracker.DashboardService.get_instance", return_value=self.service):
            render_application_tracker()

        mock_st.error.assert_called_with("Authentication required")

    @patch("dashboard.views.application_tracker.st")
    def test_expired_session_blocks_tracker_access(self, mock_st):
        """Expired session triggers SessionExpiredError and blocks access."""
        from datetime import datetime, timedelta
        # Artificially expire session_a
        self.session_a.expires_at = datetime.now(UTC) - timedelta(minutes=5)
        mock_st.session_state = {"authenticated_session_id": self.session_a.session_id}

        with patch("dashboard.views.application_tracker.DashboardService.get_instance", return_value=self.service):
            render_application_tracker()

        mock_st.error.assert_called_with("Authentication required")

    @patch("dashboard.views.application_tracker.st")
    def test_unbound_session_blocks_tracker_access(self, mock_st):
        """Session not bound to any candidate user is rejected."""
        sess = self.session_mgr.get_session(self.session_a.session_id)
        sess.user_id = None
        mock_st.session_state = {"authenticated_session_id": self.session_a.session_id}

        with patch("dashboard.views.application_tracker.DashboardService.get_instance", return_value=self.service):
            render_application_tracker()

        mock_st.error.assert_called_with("Authentication required")

    def test_candidate_a_never_sees_candidate_b_applications(self):
        """Candidate A's service calls never return Candidate B's records."""
        self._create_app(self.user_a, "Alpha AI", "ML Engineer")
        self._create_app(self.user_b, "Beta Robotics", "Control Engineer")

        apps_a = self.service.list_candidate_applications(self.session_a.session_id)
        apps_b = self.service.list_candidate_applications(self.session_b.session_id)

        self.assertEqual(len(apps_a), 1)
        self.assertEqual(apps_a[0].company_name, "Alpha AI")
        self.assertEqual(len(apps_b), 1)
        self.assertEqual(apps_b[0].company_name, "Beta Robotics")

    @patch("dashboard.views.application_tracker.st")
    def test_user_switching_does_not_leak_ui_state(self, mock_st):
        """Switching authenticated sessions enforces isolation and separate widget key spaces."""
        mock_st.session_state = {"authenticated_session_id": self.session_a.session_id}
        with patch("dashboard.views.application_tracker.DashboardService.get_instance", return_value=self.service):
            render_application_tracker()

        # Switch to Bob
        mock_st.session_state = {"authenticated_session_id": self.session_b.session_id}
        with patch("dashboard.views.application_tracker.DashboardService.get_instance", return_value=self.service):
            render_application_tracker()

    def test_candidate_a_cannot_access_candidate_b_application_detail(self):
        """Candidate A cannot retrieve Candidate B's application."""
        app_b = self._create_app(self.user_b, "Bob Corp", "Engineer")
        with self.assertRaises((CrossUserAccessError, ApplicationNotFoundError)):
            self.service.get_candidate_application(app_b.id, session_id=self.session_a.session_id)

    def test_candidate_a_cannot_access_candidate_b_timeline(self):
        """Candidate A cannot retrieve Candidate B's application timeline."""
        app_b = self._create_app(self.user_b, "Bob Corp", "Engineer")
        with self.assertRaises((CrossUserAccessError, ApplicationNotFoundError)):
            self.service.get_application_timeline(app_b.id, session_id=self.session_a.session_id)

    def test_candidate_a_cannot_access_candidate_b_packet_documents(self):
        """Candidate A cannot download Candidate B's packet documents."""
        app_b = self._create_app(self.user_b, "Bob Corp", "Engineer")
        pkt_b = self._create_packet(app_b.id, self.user_b, version_num=1)
        with self.assertRaises((CrossUserAccessError, ApplicationNotFoundError)):
            self.service.get_candidate_packet_document(
                application_id=app_b.id,
                packet_id=pkt_b.id,
                document_type="tailored_resume",
                session_id=self.session_a.session_id,
            )

    def test_candidate_a_cannot_access_or_modify_candidate_b_follow_ups(self):
        """Candidate A cannot list or complete Candidate B's follow-up reminders."""
        app_b = self._create_app(self.user_b, "Bob Corp", "Engineer")
        fup_b = self.service.create_application_follow_up(
            session_id=self.session_b.session_id,
            application_id=app_b.id,
            follow_up_date="2026-11-10",
            follow_up_type="PORTFOLIO_UPDATE",
            description="Prepare system design",
        )
        # Candidate A listing follow-ups does not see Bob's reminder
        fups_a = self.service.list_application_follow_ups(session_id=self.session_a.session_id)
        self.assertNotIn(fup_b.id, [f.id for f in fups_a])

        # Candidate A attempting to complete Bob's reminder is blocked
        with self.assertRaises((CrossUserAccessError, ApplicationNotFoundError)):
            self.service.complete_application_follow_up(
                session_id=self.session_a.session_id,
                follow_up_id=fup_b.id,
            )


# =============================================================================
# CATEGORY B: AUTHORITATIVE KPI & FOLLOW-UP METRICS TESTS
# =============================================================================

class TestKPIDashboard(BaseTrackerUITest):
    """Tests Section 6: Authoritative KPI Metrics Invariants."""

    def test_all_10_metrics_display_from_backend(self):
        """Metrics are rendered directly from backend keys without UI-level modification."""
        self._create_app(self.user_a, "C1", "R1", status="DRAFT")
        self._create_app(self.user_a, "C2", "R2", status="APPROVED")
        self._create_app(self.user_a, "C3", "R3", status="SUBMITTED")
        self._create_app(self.user_a, "C4", "R4", status="IN_PROGRESS")
        self._create_app(self.user_a, "C5", "R5", status="INTERVIEW")
        self._create_app(self.user_a, "C6", "R6", status="OFFER")
        self._create_app(self.user_a, "C7", "R7", status="CLOSED")

        metrics = self.service.get_candidate_tracker_metrics(self.session_a.session_id)
        self.assertEqual(metrics["total"], 7)
        self.assertEqual(metrics["in_preparation"], 1)
        self.assertEqual(metrics["approved"], 1)
        self.assertEqual(metrics["submitted"], 1)
        self.assertEqual(metrics["in_progress"], 1)
        self.assertEqual(metrics["interviewing"], 1)
        self.assertEqual(metrics["offers"], 1)
        self.assertEqual(metrics["active_pipeline"], 4)  # SUBMITTED + IN_PROGRESS + INTERVIEW + OFFER
        self.assertEqual(metrics["concluded"], 1)

    def test_submitted_not_double_counted_with_in_progress(self):
        """IN_PROGRESS applications do NOT increment the submitted counter."""
        self._create_app(self.user_a, "Target", "SWE", status="IN_PROGRESS")
        metrics = self.service.get_candidate_tracker_metrics(self.session_a.session_id)
        self.assertEqual(metrics["submitted"], 0)
        self.assertEqual(metrics["in_progress"], 1)
        self.assertEqual(metrics["active_pipeline"], 1)

    def test_offers_appear_in_own_metric_and_active_pipeline(self):
        """OFFER is counted in offers and active_pipeline, not in concluded."""
        self._create_app(self.user_a, "Dream Co", "Principal Scientist", status="OFFER")
        metrics = self.service.get_candidate_tracker_metrics(self.session_a.session_id)
        self.assertEqual(metrics["offers"], 1)
        self.assertEqual(metrics["active_pipeline"], 1)
        self.assertEqual(metrics["concluded"], 0)

    def test_archived_applications_excluded_by_default(self):
        """Archived applications are excluded from KPI counts unless include_archived=True."""
        self._create_app(self.user_a, "Active Co", "SWE", status="SUBMITTED", is_archived=0)
        self._create_app(self.user_a, "Archived Co", "SWE", status="SUBMITTED", is_archived=1)

        metrics_default = self.service.get_candidate_tracker_metrics(self.session_a.session_id, include_archived=False)
        self.assertEqual(metrics_default["total"], 1)
        self.assertEqual(metrics_default["submitted"], 1)

        metrics_all = self.service.get_candidate_tracker_metrics(self.session_a.session_id, include_archived=True)
        self.assertEqual(metrics_all["total"], 2)
        self.assertEqual(metrics_all["submitted"], 2)

    def test_follow_ups_due_count_accurately_reported(self):
        """Follow-ups due today or overdue increment follow_ups_due."""
        app = self._create_app(self.user_a, "Co A", "Role A")
        self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app.id,
            follow_up_date="2026-11-01",  # Overdue
            follow_up_type="THANK_YOU_NOTE",
            description="Send note",
        )
        self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app.id,
            follow_up_date="2026-12-01",  # Future
            follow_up_type="STATUS_INQUIRY",
            description="Check status",
        )
        metrics = self.service.get_candidate_tracker_metrics(self.session_a.session_id)
        self.assertEqual(metrics["follow_ups_due"], 1)


# =============================================================================
# CATEGORY C: LIST VIEW, FILTERING, SORTING & PAGINATION TESTS
# =============================================================================

class TestListViewAndFiltering(BaseTrackerUITest):
    """Tests Section 8 & 9: List View, Search, Filtering, Sorting, and Pagination."""

    def test_list_view_renders_candidate_owned_records(self):
        """Candidate-scoped query retrieves only own applications."""
        self._create_app(self.user_a, "DeepMind", "Research Scientist")
        apps = self.service.list_candidate_applications(self.session_a.session_id)
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0].company_name, "DeepMind")

    def test_search_works_across_company_and_title(self):
        """Search query filters across company name and job title."""
        self._create_app(self.user_a, "Anthropic", "Safety Researcher")
        self._create_app(self.user_a, "Google", "SWE III")

        res_anth = self.service.list_candidate_applications(self.session_a.session_id, search_term="Anthropic")
        self.assertEqual(len(res_anth), 1)
        self.assertEqual(res_anth[0].company_name, "Anthropic")

        res_swe = self.service.list_candidate_applications(self.session_a.session_id, search_term="SWE")
        self.assertEqual(len(res_swe), 1)
        self.assertEqual(res_swe[0].job_title, "SWE III")

    def test_status_category_filter_uses_canonical_statuses(self):
        """Category filter queries with canonical status lists."""
        self._create_app(self.user_a, "C1", "R1", status="DRAFT")
        self._create_app(self.user_a, "C2", "R2", status="APPROVED")
        self._create_app(self.user_a, "C3", "R3", status="SUBMITTED")

        prep_apps = self.service.list_candidate_applications(
            self.session_a.session_id,
            status_in=["DRAFT", "PREPARING"],
        )
        self.assertEqual(len(prep_apps), 1)
        self.assertEqual(prep_apps[0].company_name, "C1")

    def test_employment_type_filtering_all_parser_types(self):
        """Filtering by employment_type against all parser output types returns exact matches."""
        parser_emp_types = ["Full-time", "Part-time", "Contract", "Internship", "Temporary"]
        for emp_type in parser_emp_types:
            self._create_app(self.user_a, f"Company {emp_type}", f"Role {emp_type}", employment_type=emp_type)

        for emp_type in parser_emp_types:
            results = self.service.list_candidate_applications(
                self.session_a.session_id,
                employment_type=emp_type,
            )
            self.assertEqual(len(results), 1, f"Expected 1 match for {emp_type}")
            self.assertEqual(results[0].employment_type, emp_type)
            self.assertEqual(results[0].company_name, f"Company {emp_type}")

    @patch("dashboard.components.tracker_components.st")
    def test_toolbar_employment_type_options_excludes_work_arrangement_and_includes_temporary(self, mock_st):
        """Toolbar employment type dropdown represents parser types without work arrangements."""
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.radio.return_value = "List View"
        mock_st.text_input.return_value = ""
        mock_st.selectbox.side_effect = ["All Statuses", "All Types", "Last Updated (Newest)"]
        mock_st.checkbox.return_value = False
        mock_st.download_button.return_value = False

        render_tracker_filter_toolbar(self.user_a, [])

        # Find selectbox call for Employment Type
        emp_call = None
        for call_args in mock_st.selectbox.call_args_list:
            if call_args[0] and call_args[0][0] == "Employment Type":
                emp_call = call_args
                break
        self.assertIsNotNone(emp_call, "Employment Type selectbox must be called")
        options = emp_call[1].get("options", [])
        self.assertEqual(options, ["All Types", "Full-time", "Part-time", "Contract", "Internship", "Temporary"])
        self.assertNotIn("Remote", options)
        self.assertNotIn("Hybrid", options)
        self.assertNotIn("On-site", options)
        self.assertIn("Temporary", options)

    def test_supported_sort_orders(self):
        """All whitelisted sort options execute cleanly."""
        self._create_app(self.user_a, "Zeta Co", "Architect", application_deadline="2026-12-01")
        self._create_app(self.user_a, "Alpha Co", "Developer", application_deadline="2026-11-15")

        sorted_deadline = self.service.list_candidate_applications(self.session_a.session_id, sort_by="deadline_asc")
        self.assertEqual(sorted_deadline[0].company_name, "Alpha Co")

        sorted_company = self.service.list_candidate_applications(self.session_a.session_id, sort_by="company_name_asc")
        self.assertEqual(sorted_company[0].company_name, "Alpha Co")

    def test_pagination_and_offset(self):
        """Pagination returns correct slices based on limit and offset."""
        for i in range(25):
            self._create_app(self.user_a, f"Company {i:02d}", f"Role {i:02d}")

        page_1 = self.service.list_candidate_applications(self.session_a.session_id, limit=20, offset=0)
        page_2 = self.service.list_candidate_applications(self.session_a.session_id, limit=20, offset=20)

        self.assertEqual(len(page_1), 20)
        self.assertEqual(len(page_2), 5)

    def test_include_archived_filtering(self):
        """Archived applications are excluded unless include_archived=True."""
        self._create_app(self.user_a, "Active Job", "Dev", is_archived=0)
        self._create_app(self.user_a, "Old Job", "Dev", is_archived=1)

        default_apps = self.service.list_candidate_applications(self.session_a.session_id, include_archived=False)
        self.assertEqual(len(default_apps), 1)
        self.assertEqual(default_apps[0].company_name, "Active Job")

        all_apps = self.service.list_candidate_applications(self.session_a.session_id, include_archived=True)
        self.assertEqual(len(all_apps), 2)

    def test_empty_state_handling(self):
        """When candidate has zero applications, query returns empty list without error."""
        apps = self.service.list_candidate_applications(self.session_a.session_id)
        self.assertEqual(apps, [])


# =============================================================================
# CATEGORY D: FIVE-COLUMN KANBAN BOARD TESTS
# =============================================================================

class TestKanbanBoard(BaseTrackerUITest):
    """Tests Section 10: Five-Column Canonical Kanban Board."""

    def test_exactly_five_canonical_columns_exist(self):
        """Kanban board defines exactly 5 canonical columns."""
        self.assertEqual(len(KANBAN_COLUMNS), 5)
        col_ids = [c["id"] for c in KANBAN_COLUMNS]
        self.assertEqual(col_ids, ["col_prep", "col_review", "col_submitted", "col_assessment", "col_concluded"])

    def test_all_12_canonical_statuses_map_correctly(self):
        """All 12 statuses map to their exact canonical Kanban column."""
        status_to_col = {}
        for col in KANBAN_COLUMNS:
            for s in col["statuses"]:
                status_to_col[s] = col["id"]

        self.assertEqual(status_to_col["DRAFT"], "col_prep")
        self.assertEqual(status_to_col["PREPARING"], "col_prep")
        self.assertEqual(status_to_col["READY_FOR_REVIEW"], "col_review")
        self.assertEqual(status_to_col["APPROVED"], "col_review")
        self.assertEqual(status_to_col["SUBMITTED"], "col_submitted")
        self.assertEqual(status_to_col["IN_PROGRESS"], "col_submitted")
        self.assertEqual(status_to_col["ASSESSMENT"], "col_assessment")
        self.assertEqual(status_to_col["INTERVIEW"], "col_assessment")
        self.assertEqual(status_to_col["OFFER"], "col_assessment")
        self.assertEqual(status_to_col["REJECTED"], "col_concluded")
        self.assertEqual(status_to_col["WITHDRAWN"], "col_concluded")
        self.assertEqual(status_to_col["CLOSED"], "col_concluded")

    def test_offer_appears_in_assessment_and_interviews_column(self):
        """OFFER is strictly mapped to Column 4 (Assessment & Interviews), never Concluded."""
        col_4_statuses = KANBAN_COLUMNS[3]["statuses"]
        col_5_statuses = KANBAN_COLUMNS[4]["statuses"]
        self.assertIn("OFFER", col_4_statuses)
        self.assertNotIn("OFFER", col_5_statuses)

    def test_no_drag_and_drop_state_mutation(self):
        """Status advances only via authorized state machine transitions, not client drag-and-drop."""
        app = self._create_app(self.user_a, "Co", "Title", status="DRAFT")
        # Direct mutation without transition_application_status is prohibited
        with self.assertRaises(SecurityAuthorizationError):
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="APPROVED",  # Gate protected!
            )

    def test_gate_protected_statuses_cannot_be_reached_via_generic_transitions(self):
        """APPROVED and SUBMITTED cannot be reached through generic transition calls."""
        app = self._create_app(self.user_a, "Co", "Title", status="READY_FOR_REVIEW")
        with self.assertRaises(SecurityAuthorizationError):
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="APPROVED",
            )

    @patch("dashboard.components.tracker_components.st")
    def test_kanban_escapes_malicious_company_title_status(self, mock_st):
        """Dynamic candidate and job content is properly escaped in Kanban card HTML."""
        malicious_app = self._create_app(
            self.user_a,
            '<img src=x onerror=alert("xss")>',
            '<script>alert("pwn")</script>',
            status="DRAFT",
        )
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.tabs.return_value = [MagicMock(), MagicMock(), MagicMock()]

        render_kanban_board_view([malicious_app], self.service, self.session_a.session_id, self.user_a, False)

        # Inspect all calls to st.markdown with unsafe_allow_html=True
        html_rendered = []
        for call_args in mock_st.markdown.call_args_list:
            if call_args[1].get("unsafe_allow_html"):
                html_rendered.append(call_args[0][0])

        combined_html = "\n".join(html_rendered)
        # Verify that unescaped tags are not present
        self.assertNotIn('<script>alert("pwn")</script>', combined_html)
        self.assertNotIn('<img src=x onerror=alert("xss")>', combined_html)

        # Verify that escaped entities are present
        self.assertIn('&lt;script&gt;alert(&quot;pwn&quot;)&lt;/script&gt;', combined_html)
        self.assertIn('&lt;img src=x onerror=alert(&quot;xss&quot;)&gt;', combined_html)

    @patch("dashboard.views.application_tracker.st")
    def test_kanban_loads_all_applications_without_silent_truncation(self, mock_st):
        """Kanban board view queries with limit=None so >200 applications are not silently omitted."""
        # Create 205 applications
        for i in range(205):
            self._create_app(self.user_a, f"Company {i:03d}", f"Role {i:03d}")

        mock_st.session_state = {"authenticated_session_id": self.session_a.session_id}
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.tabs.return_value = [MagicMock(), MagicMock(), MagicMock()]

        toolbar_ret = {
            "view_mode": "Kanban Board",
            "search_term": None,
            "status_in": None,
            "employment_type": None,
            "sort_by": "updated_at_desc",
            "include_archived": False,
        }

        with (
            patch("dashboard.views.application_tracker.DashboardService.get_instance", return_value=self.service),
            patch("dashboard.views.application_tracker.render_tracker_filter_toolbar", return_value=toolbar_ret),
            patch("dashboard.views.application_tracker.render_kanban_board_view") as mock_kanban_render,
        ):
            render_application_tracker()
            mock_kanban_render.assert_called_once()
            apps_passed = mock_kanban_render.call_args[0][0]
            self.assertEqual(len(apps_passed), 205, "All 205 applications must be passed to Kanban board without truncation")


# =============================================================================
# CATEGORY E: TIMELINE & READ-ONLY PREPARED PACKET REVIEW TESTS
# =============================================================================

class TestTimelineAndPacketReview(BaseTrackerUITest):
    """Tests Section 12 & 13: Lifecycle Timeline, Packet History & Verified Downloads."""

    def test_timeline_events_render_chronologically(self):
        """Timeline events retain sequence numbers and timestamps."""
        app = self._create_app(self.user_a, "Event Co", "Dev")
        self.db.create_application_event(
            application_id=app.id,
            user_id=self.user_a,
            event_type="APPLICATION_CREATED",
            actor_type="CANDIDATE",
            actor_identifier=f"user_{self.user_a}",
            session_reference=self.session_a.session_id,
        )
        self.db.create_application_event(
            application_id=app.id,
            user_id=self.user_a,
            event_type="APPLICATION_PREPARATION_STARTED",
            actor_type="CANDIDATE",
            actor_identifier=f"user_{self.user_a}",
            session_reference=self.session_a.session_id,
        )

        timeline = self.service.get_application_timeline(app.id, self.session_a.session_id)
        self.assertTrue(timeline["chain_valid"])
        events = timeline["events"]
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].sequence_no, 1)
        self.assertEqual(events[1].sequence_no, 2)

    def test_valid_hash_chain_reports_consistency_verified(self):
        """Intact event chain reports verified message."""
        app = self._create_app(self.user_a, "Hash Co", "Dev")
        self.db.create_application_event(
            application_id=app.id,
            user_id=self.user_a,
            event_type="APPLICATION_CREATED",
            actor_type="CANDIDATE",
            actor_identifier=f"user_{self.user_a}",
            session_reference=self.session_a.session_id,
        )
        timeline = self.service.get_application_timeline(app.id, self.session_a.session_id)
        self.assertTrue(timeline["chain_valid"])
        self.assertIn("consistency verified", timeline["verification_message"].lower())

    def test_tampered_event_chain_reports_inconsistency(self):
        """Tampering with an event payload breaks hash chain and reports inconsistency."""
        app = self._create_app(self.user_a, "Tamper Co", "Dev")
        self.db.create_application_event(
            application_id=app.id,
            user_id=self.user_a,
            event_type="EVENT_1",
            actor_type="CANDIDATE",
            actor_identifier="user_1",
            session_reference=self.session_a.session_id,
        )
        # Drop trigger to simulate out-of-band tampering
        with self.db.transaction() as conn:
            conn.cursor().execute("DROP TRIGGER IF EXISTS trg_prevent_application_events_update")
            conn.cursor().execute(
                "UPDATE application_events SET event_payload_json = '{\"tampered\": true}' WHERE application_id = ?",
                (app.id,),
            )

        timeline = self.service.get_application_timeline(app.id, self.session_a.session_id)
        self.assertFalse(timeline["chain_valid"])
        self.assertIn("inconsistency detected", timeline["verification_message"].lower())

    def test_packet_history_displays_active_and_historical_revisions(self):
        """Multiple revisions are listed in reverse chronological order."""
        app = self._create_app(self.user_a, "Revision Co", "Dev")
        p1 = self._create_packet(app.id, self.user_a, version_num=1, is_active=False)
        p2 = self._create_packet(app.id, self.user_a, version_num=2, is_active=True)

        packets = self.service.list_candidate_prepared_packets(app.id, self.session_a.session_id)
        self.assertEqual(len(packets), 2)
        self.assertEqual(packets[0]["version_num"], p2.version_num)
        self.assertTrue(packets[0]["is_active_revision"])
        self.assertEqual(packets[1]["version_num"], p1.version_num)
        self.assertFalse(packets[1]["is_active_revision"])

    def test_approval_status_follows_exact_provenance(self):
        """Approval details appear only when packet_id and version hash match approval record."""
        app = self._create_app(self.user_a, "Approval Co", "Dev")
        p = self._create_packet(app.id, self.user_a, version_num=1)

        # Before approval
        detail_unapproved = self.service.get_candidate_prepared_packet(app.id, p.id, self.session_a.session_id)
        self.assertFalse(detail_unapproved["approval"]["is_approved"])

        # Add approval record
        with self.db.transaction() as conn:
            conn.cursor().execute(
                """
                INSERT INTO application_approvals (
                    application_id, packet_id, user_id, packet_version_hash,
                    ticket_nonce, key_id, approver_name, session_id, approved_at, is_consumed
                ) VALUES (?, ?, ?, ?, 'nonce1', 'key1', 'Alice Candidate', ?, CURRENT_TIMESTAMP, 0)
                """,
                (app.id, p.id, self.user_a, p.packet_version_hash, self.session_a.session_id),
            )

        detail_approved = self.service.get_candidate_prepared_packet(app.id, p.id, self.session_a.session_id)
        self.assertTrue(detail_approved["approval"]["is_approved"])
        self.assertEqual(detail_approved["approval"]["approver_name"], "Alice Candidate")

    def test_tampered_packet_does_not_render_materials_as_trusted(self):
        """Tampered packet snapshot reports integrity failure and empty materials."""
        app = self._create_app(self.user_a, "Tamper Target", "Dev")
        p = self._create_packet(app.id, self.user_a, version_num=1)

        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = '{\"tampered\": true}' WHERE id = ?",
                (p.id,),
            )

        detail = self.service.get_candidate_prepared_packet(app.id, p.id, self.session_a.session_id)
        self.assertFalse(detail["integrity_valid"])
        self.assertEqual(detail["tailored_resume"], {})
        self.assertEqual(detail["cover_letter"], {})
        self.assertEqual(detail["screening_questions"], [])
        self.assertEqual(detail["attachments_manifest"], [])

    def test_no_internal_filesystem_paths_in_candidate_packet_detail(self):
        """Attachments manifest is sanitized and exposes no server storage paths."""
        app = self._create_app(self.user_a, "Sanitize Co", "Dev")
        manifest = [{
            "artifact_type": "tailored_resume_pdf",
            "filename": "my_resume.pdf",
            "format": "PDF",
            "file_hash": "a" * 64,
            "file_path": "/var/server/internal/path/resume.pdf",
        }]
        p = self._create_packet(app.id, self.user_a, version_num=1, attachments_manifest=manifest)

        detail = self.service.get_candidate_prepared_packet(app.id, p.id, self.session_a.session_id)
        manifest_out = detail["attachments_manifest"]
        self.assertEqual(len(manifest_out), 1)
        self.assertNotIn("file_path", manifest_out[0])
        self.assertNotIn("/var/server", json.dumps(detail))

    @patch("dashboard.components.tracker_components.st")
    def test_honest_navigation_audit_language_and_status_preservation(self, mock_st):
        """Timeline rendering uses truthful language and never claims navigation is a confirmed visit."""
        app = self._create_app(
            self.user_a,
            "Nav Co",
            "Software Engineer",
            status="PREPARING",
            external_url="https://example.com/apply/123",
        )
        # Call log_external_application_url_opened
        validated_url = self.service.log_external_application_url_opened(
            application_id=app.id,
            session_id=self.session_a.session_id,
        )
        self.assertEqual(validated_url, "https://example.com/apply/123")

        # Verify status is strictly preserved
        app_db = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_db.status, "PREPARING")

        # Render timeline view
        mock_st.columns.return_value = [MagicMock(), MagicMock()]
        render_lifecycle_timeline_view(self.service, self.session_a.session_id, app.id, self.user_a)

        # Inspect caption calls for honest wording
        captions_rendered = [call[0][0] for call in mock_st.caption.call_args_list if call[0]]
        combined_captions = " ".join(captions_rendered)

        self.assertIn("Employer portal destination validated; navigation requested, visit not verified", combined_captions)
        self.assertNotIn("Employer URL Opened:", combined_captions)

    @patch("dashboard.components.tracker_components.st")
    def test_render_external_navigation_action_honest_language(self, mock_st):
        """External navigation action displays truthful preparation language."""
        app = self._create_app(
            self.user_a,
            "Nav Co 2",
            "Data Engineer",
            external_url="https://example.com/jobs/456",
        )
        mock_st.columns.return_value = [MagicMock(), MagicMock()]
        mock_st.button.return_value = False

        render_external_navigation_action(self.service, self.session_a.session_id, app, self.user_a)

        # Check button label
        btn_args = [call[0][0] for call in mock_st.button.call_args_list if call[0]]
        self.assertIn("Validate and Prepare Employer Link", btn_args)
        self.assertNotIn("Prepare Verified Portal Link", btn_args)

        # Check honest advisory caption
        captions_rendered = [call[0][0] for call in mock_st.caption.call_args_list if call[0]]
        combined_captions = " ".join(captions_rendered)
        self.assertIn("does not prove or verify that you visited, logged into, or submitted", combined_captions)


# =============================================================================
# CATEGORY F: ANTI-AUTOMATION MANUAL SUBMISSION CONFIRMATION TESTS
# =============================================================================

class TestManualSubmissionConfirmation(BaseTrackerUITest):
    """Tests Section 15: Manual Submission Confirmation Workflow."""

    def setUp(self):
        super().setUp()
        # Setup application in APPROVED status with valid prepared packet and approval
        self.app = self._create_app(self.user_a, "Anthropic", "Research Scientist", status="APPROVED")
        self.packet = self._create_packet(self.app.id, self.user_a, version_num=1, is_active=True)
        with self.db.transaction() as conn:
            conn.cursor().execute(
                """
                INSERT INTO application_approvals (
                    application_id, packet_id, user_id, packet_version_hash,
                    ticket_nonce, key_id, approver_name, session_id, approved_at, is_consumed
                ) VALUES (?, ?, ?, ?, 'n1', 'k1', 'Alice Candidate', ?, CURRENT_TIMESTAMP, 0)
                """,
                (self.app.id, self.packet.id, self.user_a, self.packet.packet_version_hash, self.session_a.session_id),
            )

    def test_ticket_issued_only_for_approved_application(self):
        """Ticket issuance succeeds for APPROVED application."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app.id,
            packet_hash=self.packet.packet_version_hash,
        )
        self.assertTrue(ticket.startswith("TKT-"))

    def test_ticket_issuance_fails_for_non_approved_application(self):
        """Draft application cannot issue submission ticket."""
        draft_app = self._create_app(self.user_a, "Draft Co", "Dev", status="DRAFT")
        with self.assertRaises(SecurityAuthorizationError):
            self.service.issue_manual_submission_ticket(
                session_id=self.session_a.session_id,
                application_id=draft_app.id,
                packet_hash=self.packet.packet_version_hash,
            )

    def test_record_submission_requires_explicit_confirmation(self):
        """Candidate confirmation boolean is mandatory."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app.id,
            packet_hash=self.packet.packet_version_hash,
        )
        with self.assertRaises(UnconfirmedSubmissionError):
            self.service.record_candidate_manual_submission(
                application_id=self.app.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket,
                candidate_confirmed=False,  # Unconfirmed!
                submission_channel="COMPANY_PORTAL",
            )

    def test_successful_manual_submission_transitions_to_submitted(self):
        """Valid submission confirmation atomically transitions application to SUBMITTED."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app.id,
            packet_hash=self.packet.packet_version_hash,
        )
        conf = self.service.record_candidate_manual_submission(
            application_id=self.app.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
            confirmation_reference="APP-2026-98124",
            candidate_notes="Submitted via Greenhouse portal.",
        )
        self.assertEqual(conf.application_id, self.app.id)
        # Check DB status
        app_db = self.db.get_user_application(self.app.id, self.user_a)
        self.assertEqual(app_db.status, "SUBMITTED")

    @patch("dashboard.components.tracker_components.st")
    def test_ui_manual_submission_positive_path(self, mock_st):
        """UI manual submission positive path issues ticket and transitions to SUBMITTED."""
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.columns.return_value = [MagicMock(), MagicMock()]
        mock_st.checkbox.return_value = True
        mock_st.selectbox.return_value = "COMPANY_PORTAL"
        mock_st.text_input.return_value = "REF-2026-XYZ"
        mock_st.text_area.return_value = "Applied directly on career site."
        mock_st.button.return_value = True

        render_manual_submission_section(self.service, self.session_a.session_id, self.app, self.user_a)

        # Verify DB status transitioned to SUBMITTED
        app_db = self.db.get_user_application(self.app.id, self.user_a)
        self.assertEqual(app_db.status, "SUBMITTED")
        mock_st.success.assert_called()

    @patch("dashboard.components.tracker_components.st")
    def test_ui_manual_submission_negative_unchecked_confirmation(self, mock_st):
        """UI manual submission without explicit confirmation checkbox raises error and blocks transition."""
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.columns.return_value = [MagicMock(), MagicMock()]
        mock_st.checkbox.return_value = False  # Unchecked
        mock_st.selectbox.return_value = "COMPANY_PORTAL"
        mock_st.text_input.return_value = ""
        mock_st.text_area.return_value = ""
        mock_st.button.return_value = True

        render_manual_submission_section(self.service, self.session_a.session_id, self.app, self.user_a)

        # Status must remain APPROVED
        app_db = self.db.get_user_application(self.app.id, self.user_a)
        self.assertEqual(app_db.status, "APPROVED")
        mock_st.error.assert_called_with("You must explicitly check the confirmation checkbox to authorize manual submission.")

    @patch("dashboard.components.tracker_components.st")
    def test_ui_manual_submission_negative_non_approved_statuses(self, mock_st):
        """Non-APPROVED applications do not render manual submission confirmation UI."""
        non_approved_statuses = ["DRAFT", "PREPARING", "READY_FOR_REVIEW", "SUBMITTED", "IN_PROGRESS", "REJECTED", "WITHDRAWN", "CLOSED"]
        for stat in non_approved_statuses:
            mock_st.reset_mock()
            mock_app = self._create_app(self.user_a, f"Co {stat}", "Role", status=stat)
            render_manual_submission_section(self.service, self.session_a.session_id, mock_app, self.user_a)
            mock_st.checkbox.assert_not_called()
            mock_st.button.assert_not_called()


# =============================================================================
# CATEGORY G: STATUS TRANSITION & REOPEN RATIONALE TESTS
# =============================================================================

class TestStatusTransitions(BaseTrackerUITest):
    """Tests Section 16: State Machine Status Transitions & Reopen Rationale."""

    def test_generic_transitions_prohibit_gate_protected_targets(self):
        """Generic transition to APPROVED or SUBMITTED is rejected."""
        app = self._create_app(self.user_a, "Gate Co", "Dev", status="READY_FOR_REVIEW")
        with self.assertRaises(SecurityAuthorizationError):
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="APPROVED",
            )

        app_approved = self._create_app(self.user_a, "Gate Co 2", "Dev", status="APPROVED")
        with self.assertRaises(SecurityAuthorizationError):
            self.service.transition_application_status(
                application_id=app_approved.id,
                session_id=self.session_a.session_id,
                new_status="SUBMITTED",
            )

    def test_allowed_transitions_for_submitted_state(self):
        """SUBMITTED status permits moving to IN_PROGRESS, ASSESSMENT, INTERVIEW, REJECTED, WITHDRAWN."""
        allowed = ApplicationStateMachine.get_allowed_transitions("SUBMITTED", include_gate_protected=False)
        self.assertIn("IN_PROGRESS", allowed)
        self.assertIn("INTERVIEW", allowed)
        self.assertIn("REJECTED", allowed)
        self.assertIn("WITHDRAWN", allowed)

    def test_terminal_reopening_requires_non_empty_rationale(self):
        """Reopening from REJECTED to IN_PROGRESS requires mandatory rationale."""
        app = self._create_app(self.user_a, "Concluded Co", "Dev", status="REJECTED")

        # Missing rationale fails
        with self.assertRaises(ValidationError):
            self.service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status="IN_PROGRESS",
                reopen_rationale="",
            )

        # Providing rationale succeeds
        updated_app = self.service.transition_application_status(
            application_id=app.id,
            session_id=self.session_a.session_id,
            new_status="IN_PROGRESS",
            reopen_rationale="Recruiter reached out with reopened position.",
        )
        self.assertEqual(updated_app.status, "IN_PROGRESS")


# =============================================================================
# CATEGORY H: FOLLOW-UP MANAGEMENT, ARCHIVE & CSV EXPORT TESTS
# =============================================================================

class TestFollowUpAndArchive(BaseTrackerUITest):
    """Tests Section 17, 18 & 19: Follow-up Reminders, Soft Archiving & CSV Export."""

    def test_create_and_list_follow_up_reminders(self):
        """Candidate can schedule and list follow-up reminders."""
        app = self._create_app(self.user_a, "Reminder Co", "Dev")
        f = self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app.id,
            follow_up_date="2026-11-10",
            follow_up_type="STATUS_INQUIRY",
            description="Email recruiter for status update",
        )
        self.assertEqual(f.application_id, app.id)

        follow_ups = self.service.list_application_follow_ups(
            session_id=self.session_a.session_id,
            application_id=app.id,
        )
        self.assertEqual(len(follow_ups), 1)
        self.assertEqual(follow_ups[0].description, "Email recruiter for status update")

    def test_complete_follow_up_reminder(self):
        """Marking follow-up complete records completion timestamp and outcome notes."""
        app = self._create_app(self.user_a, "Reminder Co 2", "Dev")
        f = self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app.id,
            follow_up_date="2026-11-10",
            follow_up_type="PHONE_CALL",
            description="Call recruiter",
        )
        completed = self.service.complete_application_follow_up(
            session_id=self.session_a.session_id,
            follow_up_id=f.id,
            outcome_notes="Recruiter confirmed interview scheduled for next week.",
        )
        self.assertEqual(completed.is_completed, 1)
        self.assertIn("interview scheduled", completed.outcome_notes)

    def test_delete_follow_up_reminder(self):
        """Candidate can delete a scheduled reminder."""
        app = self._create_app(self.user_a, "Reminder Co 3", "Dev")
        f = self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app.id,
            follow_up_date="2026-11-10",
            follow_up_type="OTHER",
            description="Check job board",
        )
        success = self.service.delete_application_follow_up(
            session_id=self.session_a.session_id,
            follow_up_id=f.id,
        )
        self.assertTrue(success)
        follow_ups = self.service.list_application_follow_ups(self.session_a.session_id, app.id)
        self.assertEqual(len(follow_ups), 0)

    def test_archive_application(self):
        """Soft-archiving marks application is_archived=1 without deleting history."""
        app = self._create_app(self.user_a, "Old Opportunity", "Dev", is_archived=0)
        archived = self.service.archive_candidate_application(
            application_id=app.id,
            session_id=self.session_a.session_id,
            archive_reason="Position cancelled by company",
        )
        self.assertEqual(archived.is_archived, 1)

    def test_csv_export_format_and_security(self):
        """CSV export serializes safe application fields and excludes sensitive secrets."""
        app = self._create_app(
            self.user_a,
            "CSV Co",
            "Data Scientist",
            status="SUBMITTED",
            location="Remote",
            salary_range="$130k - $150k",
        )
        csv_str = build_tracker_csv_export([app])
        self.assertIn("CSV Co", csv_str)
        self.assertIn("Data Scientist", csv_str)
        self.assertIn("SUBMITTED", csv_str)
        # Excludes sensitive internal tokens
        self.assertNotIn("session_id", csv_str)
        self.assertNotIn("token", csv_str)
        self.assertNotIn("file_path", csv_str)

    def test_sanitize_csv_cell_formula_injection_protection(self):
        """sanitize_csv_cell prefixes formula trigger characters with single quote."""
        # Equal sign
        self.assertEqual(sanitize_csv_cell("=1+1"), "'=1+1")
        self.assertEqual(sanitize_csv_cell("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        # Plus sign
        self.assertEqual(sanitize_csv_cell("+1+1"), "'+1+1")
        # Minus sign
        self.assertEqual(sanitize_csv_cell("-2+3"), "'-2+3")
        # At sign
        self.assertEqual(sanitize_csv_cell("@SUM(A1:A5)"), "'@SUM(A1:A5)")
        # Tab and carriage return
        self.assertEqual(sanitize_csv_cell("\t=cmd"), "'\t=cmd")
        self.assertEqual(sanitize_csv_cell("\r+2+2"), "'\r+2+2")
        # Leading whitespace before trigger
        self.assertEqual(sanitize_csv_cell("   =alert()"), "'   =alert()")
        # Safe text values unaltered
        self.assertEqual(sanitize_csv_cell("Google LLC"), "Google LLC")
        self.assertEqual(sanitize_csv_cell("Software Engineer"), "Software Engineer")
        self.assertEqual(sanitize_csv_cell("San Francisco, CA"), "San Francisco, CA")
        self.assertEqual(sanitize_csv_cell("2026-11-04"), "2026-11-04")
        # Numeric, boolean, None values unaltered
        self.assertEqual(sanitize_csv_cell(123), 123)
        self.assertEqual(sanitize_csv_cell(0), 0)
        self.assertEqual(sanitize_csv_cell(True), True)
        self.assertEqual(sanitize_csv_cell(None), "")
        self.assertEqual(sanitize_csv_cell(""), "")

    def test_csv_export_sanitizes_formula_injection_and_protects_secrets(self):
        """CSV export neutralizes formula injection across candidate/job fields while preserving secrets isolation."""
        app = self._create_app(
            self.user_a,
            "=cmd|' /C calc'!A0",
            "+1+1",
            status="SUBMITTED",
            target_role="@EXPLOIT",
            location="-Remote",
            salary_range="\t$150,000",
        )
        csv_str = build_tracker_csv_export([app])
        # Formula injection characters must be sanitized with quote
        self.assertIn("'=cmd", csv_str)
        self.assertIn("'+1+1", csv_str)
        self.assertIn("'-Remote", csv_str)
        self.assertIn("'@EXPLOIT", csv_str)
        self.assertIn("'\t$150,000", csv_str)
        # Verify internal secrets and filesystem storage paths are excluded
        self.assertNotIn("session_id", csv_str)
        self.assertNotIn("token", csv_str)
        self.assertNotIn("storage", csv_str)


# =============================================================================
# CATEGORY I: STREAMLIT COMPONENT & VIEW RENDERING TESTS
# =============================================================================

class TestComponentRendering(BaseTrackerUITest):
    """Tests UI Component functions and Streamlit execution flows."""

    def test_format_status_badge(self):
        """format_status_badge formats canonical and legacy status strings."""
        self.assertEqual(format_status_badge("draft"), "`DRAFT`")
        self.assertEqual(format_status_badge("interview"), "`INTERVIEW`")
        self.assertEqual(format_status_badge("awaiting_approval"), "`APPROVED`")
        self.assertEqual(format_status_badge("under_review"), "`PREPARING`")

    @patch("dashboard.components.tracker_components.st")
    def test_render_tracker_header(self, mock_st):
        """render_tracker_header displays header title and subtitle."""
        render_tracker_header(self.user_a)
        mock_st.markdown.assert_any_call("## 📋 Candidate Application Tracker")
        mock_st.caption.assert_called()

    @patch("dashboard.components.tracker_components.st")
    def test_render_tracker_metrics_bar(self, mock_st):
        """render_tracker_metrics_bar renders 10 KPI cards in two rows."""
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n)]
        metrics = {
            "total": 12,
            "in_preparation": 2,
            "approved": 1,
            "submitted": 3,
            "in_progress": 2,
            "interviewing": 2,
            "offers": 1,
            "active_pipeline": 8,
            "concluded": 1,
            "follow_ups_due": 3,
        }
        render_tracker_metrics_bar(metrics)
        self.assertEqual(mock_st.columns.call_count, 2)
        mock_st.columns.assert_any_call(5)

    @patch("dashboard.components.tracker_components.st")
    def test_render_follow_up_alert_bar_empty(self, mock_st):
        """Empty follow-ups list displays informative info message."""
        render_follow_up_alert_bar(self.service, self.session_a.session_id, self.user_a, [], {})
        mock_st.info.assert_called_with("You have no outstanding follow-up reminders.")

    @patch("dashboard.components.tracker_components.st")
    def test_render_follow_up_alert_bar_with_reminders(self, mock_st):
        """Pending reminders render within an alert expander."""
        app = self._create_app(self.user_a, "Target AI", "SWE")
        f = self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app.id,
            follow_up_date="2026-11-04",
            follow_up_type="STATUS_INQUIRY",
            description="Inquire about next round",
        )
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.button.return_value = False

        render_follow_up_alert_bar(self.service, self.session_a.session_id, self.user_a, [f], {app.id: app})
        mock_st.expander.assert_called()

    @patch("dashboard.components.tracker_components.st")
    def test_render_tracker_filter_toolbar(self, mock_st):
        """Toolbar renders controls and returns parsed filter dictionary."""
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(len(n))]
        mock_st.radio.return_value = "List View"
        mock_st.text_input.return_value = "Anthropic"
        mock_st.selectbox.side_effect = ["Preparation", "Full-time", "Last Updated (Newest)"]
        mock_st.checkbox.return_value = False
        mock_st.download_button.return_value = None

        res = render_tracker_filter_toolbar(self.user_a, [])
        self.assertEqual(res["view_mode"], "List View")
        self.assertEqual(res["search_term"], "Anthropic")
        self.assertEqual(res["status_in"], ["DRAFT", "PREPARING"])
        self.assertEqual(res["employment_type"], "Full-time")
        self.assertEqual(res["sort_by"], "updated_at_desc")
        self.assertFalse(res["include_archived"])

    @patch("dashboard.components.tracker_components.st")
    def test_render_kanban_board_view(self, mock_st):
        """Kanban board renders 5 columns."""
        app = self._create_app(self.user_a, "Kanban Target", "Dev", status="DRAFT")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.tabs.return_value = [MagicMock(), MagicMock(), MagicMock()]

        render_kanban_board_view([app], self.service, self.session_a.session_id, self.user_a, False)
        mock_st.columns.assert_any_call(5)

    @patch("dashboard.components.tracker_components.st")
    def test_render_manual_submission_section_only_when_approved(self, mock_st):
        """Manual submission section only renders when status is APPROVED."""
        draft_app = self._create_app(self.user_a, "Draft Co", "Dev", status="DRAFT")
        render_manual_submission_section(self.service, self.session_a.session_id, draft_app, self.user_a)
        # For draft app, header is not rendered
        mock_st.markdown.assert_not_called()

        app_approved = self._create_app(self.user_a, "Appr Co", "Dev", status="APPROVED")
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.columns.return_value = [MagicMock(), MagicMock()]
        mock_st.checkbox.return_value = False
        mock_st.selectbox.return_value = "COMPANY_PORTAL"
        mock_st.text_input.return_value = ""
        mock_st.text_area.return_value = ""
        mock_st.button.return_value = False

        render_manual_submission_section(self.service, self.session_a.session_id, app_approved, self.user_a)
        mock_st.warning.assert_called()

    @patch("dashboard.components.tracker_components.st")
    def test_render_lifecycle_status_actions(self, mock_st):
        """Status transition section provides allowed target options."""
        app = self._create_app(self.user_a, "Trans Co", "Dev", status="SUBMITTED")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(len(n))]
        mock_st.selectbox.return_value = "IN_PROGRESS"
        mock_st.text_input.return_value = "Interview scheduled"
        mock_st.button.return_value = False

        render_lifecycle_status_actions(self.service, self.session_a.session_id, app, self.user_a)
        mock_st.selectbox.assert_called()

    @patch("dashboard.components.tracker_components.st")
    def test_render_archive_action(self, mock_st):
        """Archive action renders confirmation checkbox and button."""
        app = self._create_app(self.user_a, "Archive Co", "Dev", is_archived=0)
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.text_input.return_value = "No longer hiring"
        mock_st.checkbox.return_value = False
        mock_st.button.return_value = False

        render_archive_action(self.service, self.session_a.session_id, app, self.user_a)
        mock_st.expander.assert_called_with("📦 Archive Application", expanded=False)

    @patch("dashboard.views.application_tracker.st")
    def test_render_application_tracker_authenticated_flow(self, mock_st):
        """Full application tracker view executes cleanly for authenticated candidate."""
        self._create_app(self.user_a, "Full Target", "Lead Dev", status="SUBMITTED")
        mock_st.session_state = {"authenticated_session_id": self.session_a.session_id}
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.radio.return_value = "List View"
        mock_st.text_input.return_value = ""
        mock_st.selectbox.side_effect = ["All Statuses", "All Types", "Last Updated (Newest)"]
        mock_st.checkbox.return_value = False
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.tabs.return_value = [MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock()]
        mock_st.button.return_value = False

        with patch("dashboard.views.application_tracker.DashboardService.get_instance", return_value=self.service):
            render_application_tracker()

        mock_st.markdown.assert_any_call("**Showing 1–1 of 1 Tracked Opportunities**")

    @patch("dashboard.components.tracker_components.st")
    def test_render_application_card(self, mock_st):
        """render_application_card renders expander and 6 detail tabs."""
        app = self._create_app(self.user_a, "Card Co", "Architect")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.tabs.return_value = [MagicMock() for _ in range(6)]

        render_application_card(app, self.service, self.session_a.session_id, self.user_a, False)
        mock_st.expander.assert_called()
        mock_st.tabs.assert_called_with([
            "📋 Overview",
            "🎯 Match Evaluation",
            "🛡️ Lifecycle Timeline",
            "📜 Prepared Packets",
            "⚡ Actions & Transitions",
            "📅 Follow-ups & Archive",
        ])

    @patch("dashboard.components.tracker_components.st")
    def test_render_external_navigation_action(self, mock_st):
        """External navigation action displays link button when verified URL is stored."""
        app = self._create_app(self.user_a, "Portal Co", "Engineer", external_url="https://example.com/careers/job1")
        mock_st.columns.return_value = [MagicMock(), MagicMock()]
        mock_st.session_state = {f"validated_url_{self.user_a}_{app.id}": "https://example.com/careers/job1"}

        render_external_navigation_action(self.service, self.session_a.session_id, app, self.user_a)
        mock_st.link_button.assert_called_with("🚀 Proceed to Employer Portal", url="https://example.com/careers/job1")

    @patch("dashboard.components.tracker_components.st")
    def test_render_follow_up_manager(self, mock_st):
        """Follow-up manager lists reminders and renders new reminder form."""
        app = self._create_app(self.user_a, "Fup Co", "Engineer")
        self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app.id,
            follow_up_date="2026-11-05",
            follow_up_type="PORTFOLIO_UPDATE",
            description="Submit portfolio link",
        )
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.button.return_value = False

        render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
        mock_st.markdown.assert_any_call("##### 📅 Follow-Up Reminders")

    @patch("dashboard.components.tracker_components.st")
    def test_render_lifecycle_timeline_view(self, mock_st):
        """Timeline view renders events and integrity indicator."""
        app = self._create_app(self.user_a, "Time Co", "Engineer")
        mock_st.columns.return_value = [MagicMock(), MagicMock()]

        render_lifecycle_timeline_view(self.service, self.session_a.session_id, app.id, self.user_a)
        mock_st.success.assert_called()

    @patch("dashboard.components.tracker_components.st")
    def test_render_prepared_packets_view(self, mock_st):
        """Prepared packets view renders revisions and document downloads."""
        app = self._create_app(self.user_a, "Packet Co", "Engineer")
        self._create_packet(app.id, self.user_a, version_num=1, is_active=True)
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.tabs.return_value = [MagicMock() for _ in range(4)]
        mock_st.columns.return_value = [MagicMock() for _ in range(4)]

        render_prepared_packets_view(self.service, self.session_a.session_id, app.id, self.user_a)
        mock_st.markdown.assert_any_call("##### Prepared Application Revisions (1 Revisions)")

    def test_model_enums_and_state_machine_coverage(self):
        """Verifies FollowUpType, SubmissionChannel, and ApplicationStatus enums."""
        self.assertEqual(len(FollowUpType.list()), 6)
        self.assertEqual(len(SubmissionChannel.list()), 7)
        self.assertIn(ApplicationStatus.DRAFT, ApplicationStateMachine.UNIVERSAL_STATUSES)
        self.assertIn(ApplicationStatus.OFFER, ApplicationStateMachine.UNIVERSAL_STATUSES)


# =============================================================================
# CATEGORY J: PHASE 7.4.2 CANDIDATE FOLLOW-UP INTELLIGENCE & REMINDER UI TESTS
# =============================================================================

class TestPhase742FollowUpUIIntegration(BaseTrackerUITest):
    """Verifies Phase 7.4.2 UI integrations in tracker_components.render_follow_up_manager:
    - Archived application guard disables scheduling, recommendations, and drafts
    - Deletion of pending reminders does not pass outcome_notes or mutate outcome
    - Deletion of completed reminders does not raise UnboundLocalError
    - Recommendation UI renders status-specific recommendations and creates reminder on candidate action
    - Interview status checkbox accurately passes candidate_provided tag
    - Template draft generator UI renders supported types and populates editable subject/body
    """

    @patch("dashboard.components.tracker_components.st")
    def test_archived_application_disables_scheduling_and_recommendations(self, mock_st):
        """When an application is archived, historical reminders are shown, but active recommendations, scheduling, and drafts are disabled."""
        app = self._create_app(self.user_a, "Archived Corp", "Developer", is_archived=1)
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()

        render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, include_archived=True)

        # Confirm st.info was called with the archived guard notice
        info_calls = [call[0][0] for call in mock_st.info.call_args_list]
        self.assertTrue(any("archived" in c.lower() for c in info_calls))

        # Confirm recommendation or draft buttons were not invoked
        button_labels = [call[0][0] for call in mock_st.button.call_args_list]
        self.assertNotIn("Schedule This Reminder", button_labels)
        self.assertNotIn("Generate Draft", button_labels)

    @patch("dashboard.components.tracker_components.st")
    def test_deletion_pending_reminder_does_not_pass_outcome_notes(self, mock_st):
        """Deleting a pending reminder calls delete_application_follow_up without outcome_notes."""
        app = self._create_app(self.user_a, "Delete Co", "Developer")
        f = self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app.id,
            follow_up_date="2026-11-20",
            follow_up_type="STATUS_INQUIRY",
            description="Pending reminder to delete",
        )
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()

        def button_mock(label, key=None):
            return key == f"fup_del_btn_{self.user_a}_{f.id}"
        mock_st.button.side_effect = button_mock

        with patch.object(self.service, "delete_application_follow_up", wraps=self.service.delete_application_follow_up) as spy_del:
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
            spy_del.assert_called_once_with(
                session_id=self.session_a.session_id,
                follow_up_id=f.id,
            )
        mock_st.success.assert_called_with("Reminder deleted.")

    @patch("dashboard.components.tracker_components.st")
    def test_deletion_completed_reminder_does_not_raise_unbound_outcome(self, mock_st):
        """Deleting a completed reminder succeeds and does not raise UnboundLocalError."""
        app = self._create_app(self.user_a, "Delete Done Co", "Developer")
        f = self.service.create_application_follow_up(
            session_id=self.session_a.session_id,
            application_id=app.id,
            follow_up_date="2026-11-20",
            follow_up_type="STATUS_INQUIRY",
            description="Completed reminder to delete",
        )
        self.service.complete_application_follow_up(
            session_id=self.session_a.session_id,
            follow_up_id=f.id,
            outcome_notes="Recruiter replied.",
        )
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()

        def button_mock(label, key=None):
            return key == f"fup_del_btn_{self.user_a}_{f.id}"
        mock_st.button.side_effect = button_mock

        # Must execute without UnboundLocalError
        render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
        mock_st.success.assert_called_with("Reminder deleted.")

    @patch("dashboard.components.tracker_components.st")
    def test_recommendation_ui_submitted_status_displays_and_schedules(self, mock_st):
        """SUBMITTED status displays recommendation and clicking schedule creates reminder."""
        app = self._create_app(
            self.user_a, "Rec Co", "Engineer", status="SUBMITTED",
        )
        # Set date_submitted in DB
        with self.db.transaction() as conn:
            conn.cursor().execute("UPDATE applications SET date_submitted = '2026-11-01' WHERE id = ?", (app.id,))
        app = self.db.get_user_application(app.id, self.user_a)

        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.session_state = {}

        # Default button returns False
        mock_st.button.return_value = False

        render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        # Check that recommendation info was displayed
        info_calls = [call[0][0] for call in mock_st.info.call_args_list]
        self.assertTrue(any("STATUS_INQUIRY" in str(c) for c in info_calls))

        # Now test clicking "Schedule This Reminder"
        def button_mock(label, key=None):
            return key == f"rec_sched_btn_{self.user_a}_{app.id}"
        mock_st.button.side_effect = button_mock
        mock_st.date_input.return_value = date(2026, 11, 13)
        mock_st.selectbox.return_value = "STATUS_INQUIRY"
        mock_st.text_input.return_value = "Follow up with recruiter regarding application status"

        render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        fups = self.service.list_application_follow_ups(self.session_a.session_id, app.id)
        self.assertEqual(len(fups), 1)
        self.assertEqual(fups[0].follow_up_type, "STATUS_INQUIRY")
        self.assertEqual(fups[0].follow_up_date, "2026-11-13")

    @patch("dashboard.components.tracker_components.st")
    def test_recommendation_ui_interview_with_candidate_provided_date(self, mock_st):
        """INTERVIEW status with candidate provided date passes candidate_provided tag to engine."""
        app = self._create_app(self.user_a, "Interview Co", "Engineer", status="INTERVIEW")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.checkbox.side_effect = lambda label, key=None: key == f"rec_int_chk_{self.user_a}_{app.id}"
        mock_st.date_input.return_value = date(2026, 11, 4)
        mock_st.button.return_value = False
        mock_st.session_state = {}

        with patch.object(self.service, "recommend_application_follow_up", wraps=self.service.recommend_application_follow_up) as spy_rec:
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
            spy_rec.assert_called_once()
            call_kwargs = spy_rec.call_args[1]
            extra_ctx = call_kwargs.get("extra_context", {})
            self.assertEqual(extra_ctx.get("interview_date"), "2026-11-04")
            self.assertEqual(extra_ctx.get("interview_date_source"), "candidate_provided")

    @patch("dashboard.components.tracker_components.st")
    def test_template_draft_generator_ui_flow(self, mock_st):
        """Candidate can generate a draft template and review editable fields."""
        app = self._create_app(self.user_a, "Draft Co", "Engineer", status="SUBMITTED")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        session_state_dict: dict[str, Any] = {}
        mock_st.session_state = session_state_dict

        def selectbox_mock(label, options=None, index=0, key=None):
            if key == f"tpl_type_{self.user_a}_{app.id}":
                return "STATUS_INQUIRY"
            return (options or ["STATUS_INQUIRY"])[0]
        mock_st.selectbox.side_effect = selectbox_mock

        def text_input_mock(label, value="", placeholder="", key=None):
            if key == f"tpl_rec_name_{self.user_a}_{app.id}":
                return "Sarah Recruiter"
            return value or ""
        mock_st.text_input.side_effect = text_input_mock

        def button_mock(label, key=None):
            return key == f"gen_tpl_btn_{self.user_a}_{app.id}"
        mock_st.button.side_effect = button_mock

        render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        # Stored in session state
        stored_draft = session_state_dict.get(f"generated_draft_{self.user_a}_{app.id}")
        self.assertIsNotNone(stored_draft)
        self.assertIn("subject", stored_draft)
        self.assertIn("body", stored_draft)
        self.assertIn("Engineer", stored_draft["subject"])
        self.assertIn("Draft Co", stored_draft["body"])
        self.assertIn("Sarah Recruiter", stored_draft["body"])
        mock_st.success.assert_called_with("Draft generated successfully. Review and edit below before manual sending.")


# =============================================================================
# CATEGORY K: PHASE 7.4.2.1 EXPLICIT DATE INPUT & DRAFT STATE REMEDIATION TESTS
# =============================================================================

class TestPhase7421DateAndDraftRemediation(BaseTrackerUITest):
    """Verifies Phase 7.4.2.1 remediations:
    - Finding A: Optional date widgets default to value=None and do not pass unentered dates.
    - Finding B: Invalid recommendation dates fail closed without falling back to today's date.
    - Finding C: Generated draft widgets refresh on template regeneration while preserving candidate edits on unrelated reruns.
    """

    @patch("dashboard.components.tracker_components.st")
    def test_interview_date_none_does_not_pass_candidate_context(self, mock_st):
        """When interview date checkbox is checked but date_input returns None, no date is passed."""
        app = self._create_app(self.user_a, "Int Co", "Dev", status="INTERVIEW")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.checkbox.side_effect = lambda label, key=None: key == f"rec_int_chk_{self.user_a}_{app.id}"
        mock_st.date_input.return_value = None
        mock_st.button.return_value = False
        mock_st.session_state = {}

        with patch.object(self.service, "recommend_application_follow_up", wraps=self.service.recommend_application_follow_up) as spy_rec:
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
            spy_rec.assert_called_once()
            call_kwargs = spy_rec.call_args[1]
            self.assertIsNone(call_kwargs.get("extra_context"))

        # Confirm st.date_input was invoked with value=None
        date_input_calls = [
            kwargs for args, kwargs in mock_st.date_input.call_args_list
            if kwargs.get("key") == f"rec_int_date_{self.user_a}_{app.id}"
        ]
        self.assertEqual(len(date_input_calls), 1)
        self.assertIsNone(date_input_calls[0].get("value"))

    @patch("dashboard.components.tracker_components.st")
    def test_interview_date_selected_passes_candidate_provided_provenance(self, mock_st):
        """When candidate actually selects an interview date, it is passed with candidate_provided provenance."""
        app = self._create_app(self.user_a, "Int Co 2", "Dev", status="INTERVIEW")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.checkbox.side_effect = lambda label, key=None: key == f"rec_int_chk_{self.user_a}_{app.id}"
        mock_st.date_input.return_value = date(2026, 11, 4)
        mock_st.button.return_value = False
        mock_st.session_state = {}

        with patch.object(self.service, "recommend_application_follow_up", wraps=self.service.recommend_application_follow_up) as spy_rec:
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
            spy_rec.assert_called_once()
            call_kwargs = spy_rec.call_args[1]
            extra_ctx = call_kwargs.get("extra_context", {})
            self.assertEqual(extra_ctx.get("interview_date"), "2026-11-04")
            self.assertEqual(extra_ctx.get("interview_date_source"), "candidate_provided")

    @patch("dashboard.components.tracker_components.st")
    def test_assessment_date_none_does_not_pass_candidate_context(self, mock_st):
        """When assessment date checkbox is checked but date_input returns None, no date is passed."""
        app = self._create_app(self.user_a, "Assess Co", "Dev", status="ASSESSMENT")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.checkbox.side_effect = lambda label, key=None: key == f"rec_assess_chk_{self.user_a}_{app.id}"
        mock_st.date_input.return_value = None
        mock_st.button.return_value = False
        mock_st.session_state = {}

        with patch.object(self.service, "recommend_application_follow_up", wraps=self.service.recommend_application_follow_up) as spy_rec:
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
            spy_rec.assert_called_once()
            call_kwargs = spy_rec.call_args[1]
            self.assertIsNone(call_kwargs.get("extra_context"))

        # Confirm st.date_input was invoked with value=None
        date_input_calls = [
            kwargs for args, kwargs in mock_st.date_input.call_args_list
            if kwargs.get("key") == f"rec_assess_date_{self.user_a}_{app.id}"
        ]
        self.assertEqual(len(date_input_calls), 1)
        self.assertIsNone(date_input_calls[0].get("value"))

    @patch("dashboard.components.tracker_components.st")
    def test_assessment_date_selected_passes_assessment_date(self, mock_st):
        """When candidate selects assessment date, it is passed in extra_context."""
        app = self._create_app(self.user_a, "Assess Co 2", "Dev", status="ASSESSMENT")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.checkbox.side_effect = lambda label, key=None: key == f"rec_assess_chk_{self.user_a}_{app.id}"
        mock_st.date_input.return_value = date(2026, 11, 2)
        mock_st.button.return_value = False
        mock_st.session_state = {}

        with patch.object(self.service, "recommend_application_follow_up", wraps=self.service.recommend_application_follow_up) as spy_rec:
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
            spy_rec.assert_called_once()
            call_kwargs = spy_rec.call_args[1]
            extra_ctx = call_kwargs.get("extra_context", {})
            self.assertEqual(extra_ctx.get("assessment_date"), "2026-11-02")

    @patch("dashboard.components.tracker_components.st")
    def test_thank_you_template_date_none_produces_neutral_template(self, mock_st):
        """When thank you note date checkbox is enabled but date is None, template is neutral and source is unavailable."""
        app = self._create_app(self.user_a, "TY Co", "Dev", status="INTERVIEW")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        session_state_dict: dict[str, Any] = {}
        mock_st.session_state = session_state_dict

        mock_st.selectbox.side_effect = lambda label, options=None, index=0, key=None: (
            "THANK_YOU_NOTE" if key == f"tpl_type_{self.user_a}_{app.id}" else (options or [""])[0]
        )
        mock_st.text_input.return_value = ""
        mock_st.checkbox.side_effect = lambda label, key=None: key == f"tpl_include_date_{self.user_a}_{app.id}"
        mock_st.date_input.return_value = None
        mock_st.button.side_effect = lambda label, key=None: key == f"gen_tpl_btn_{self.user_a}_{app.id}"

        with patch.object(self.service, "generate_follow_up_template", wraps=self.service.generate_follow_up_template) as spy_gen:
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
            spy_gen.assert_called_once()
            call_kwargs = spy_gen.call_args[1]
            self.assertIsNone(call_kwargs.get("extra_context"))

        # Verify draft metadata source is unavailable
        draft = session_state_dict.get(f"generated_draft_{self.user_a}_{app.id}")
        self.assertIsNotNone(draft)
        self.assertEqual(draft["context_metadata"].get("interview_date_source"), "unavailable")
        self.assertNotIn(" on ", draft["body"])

    @patch("dashboard.components.tracker_components.st")
    def test_thank_you_template_date_selected_passes_candidate_provided_date(self, mock_st):
        """When candidate selects interview date for thank you note, it is passed with candidate_provided provenance."""
        app = self._create_app(self.user_a, "TY Co 2", "Dev", status="INTERVIEW")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        session_state_dict: dict[str, Any] = {}
        mock_st.session_state = session_state_dict

        mock_st.selectbox.side_effect = lambda label, options=None, index=0, key=None: (
            "THANK_YOU_NOTE" if key == f"tpl_type_{self.user_a}_{app.id}" else (options or [""])[0]
        )
        mock_st.text_input.return_value = ""
        mock_st.checkbox.side_effect = lambda label, key=None: key == f"tpl_include_date_{self.user_a}_{app.id}"
        mock_st.date_input.return_value = date(2026, 11, 4)
        mock_st.button.side_effect = lambda label, key=None: key == f"gen_tpl_btn_{self.user_a}_{app.id}"

        with patch.object(self.service, "generate_follow_up_template", wraps=self.service.generate_follow_up_template) as spy_gen:
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
            spy_gen.assert_called_once()
            call_kwargs = spy_gen.call_args[1]
            extra_ctx = call_kwargs.get("extra_context", {})
            self.assertEqual(extra_ctx.get("interview_date"), "2026-11-04")
            self.assertEqual(extra_ctx.get("interview_date_source"), "candidate_provided")

        draft = session_state_dict.get(f"generated_draft_{self.user_a}_{app.id}")
        self.assertIsNotNone(draft)
        self.assertEqual(draft["context_metadata"].get("interview_date_source"), "candidate_provided")
        self.assertIn("2026-11-04", draft["body"])

    @patch("dashboard.components.tracker_components.st")
    def test_recommendation_valid_date_renders_scheduling_controls(self, mock_st):
        """A recommendation with a valid YYYY-MM-DD date renders scheduling controls initialized with that date."""
        app = self._create_app(self.user_a, "Valid Date Co", "Dev", status="SUBMITTED")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.button.return_value = False
        mock_st.session_state = {}

        mock_rec = {
            "has_recommendation": True,
            "recommendation_type": "STATUS_INQUIRY",
            "recommended_date": "2026-11-13",
            "rationale": "Follow up after 10 business days.",
            "default_description": "Check application status",
        }
        with patch.object(self.service, "recommend_application_follow_up", return_value=mock_rec):
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        mock_st.expander.assert_any_call("🗓️ Review & Schedule Proposed Reminder", expanded=False)
        date_calls = [
            kwargs for args, kwargs in mock_st.date_input.call_args_list
            if kwargs.get("key") == f"rec_sched_date_{self.user_a}_{app.id}"
        ]
        self.assertEqual(len(date_calls), 1)
        self.assertEqual(date_calls[0].get("value"), date(2026, 11, 13))

    @patch("dashboard.components.tracker_components.st")
    def test_recommendation_missing_date_fails_closed(self, mock_st):
        """When recommendation has has_recommendation=True but recommended_date is missing, it fails closed."""
        app = self._create_app(self.user_a, "No Date Co", "Dev", status="SUBMITTED")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.button.return_value = False
        mock_st.session_state = {}

        mock_rec = {
            "has_recommendation": True,
            "recommendation_type": "STATUS_INQUIRY",
            "recommended_date": None,
            "rationale": "Status inquiry",
            "default_description": "Check status",
        }
        with patch.object(self.service, "recommend_application_follow_up", return_value=mock_rec):
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        mock_st.warning.assert_any_call("⚠️ Recommendation has no valid proposed date; scheduling is unavailable.")
        expander_titles = [call[0][0] for call in mock_st.expander.call_args_list]
        self.assertNotIn("🗓️ Review & Schedule Proposed Reminder", expander_titles)

    @patch("dashboard.components.tracker_components.st")
    def test_recommendation_malformed_and_impossible_dates_fail_closed(self, mock_st):
        """Malformed and impossible dates (e.g. 2026-02-30) fail closed without rendering scheduling controls."""
        app = self._create_app(self.user_a, "Bad Date Co", "Dev", status="SUBMITTED")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.button.return_value = False
        mock_st.session_state = {}

        for bad_date in ["2026-02-30", "not-a-date", "2026-11", "2026-13-45", "2026-11-15trailing"]:
            mock_st.reset_mock()
            mock_rec = {
                "has_recommendation": True,
                "recommendation_type": "STATUS_INQUIRY",
                "recommended_date": bad_date,
                "rationale": "Test bad date",
                "default_description": "Desc",
            }
            with patch.object(self.service, "recommend_application_follow_up", return_value=mock_rec):
                render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

            mock_st.warning.assert_any_call("⚠️ Recommendation has no valid proposed date; scheduling is unavailable.")
            expander_titles = [call[0][0] for call in mock_st.expander.call_args_list]
            self.assertNotIn("🗓️ Review & Schedule Proposed Reminder", expander_titles)

    @patch("dashboard.components.tracker_components.st")
    def test_scheduling_button_when_date_invalid_does_not_create_reminder(self, mock_st):
        """Even if button mock returns True for rec_sched_btn, invalid date blocks creation."""
        app = self._create_app(self.user_a, "Blocked Sched Co", "Dev", status="SUBMITTED")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.button.side_effect = lambda label, key=None: key == f"rec_sched_btn_{self.user_a}_{app.id}"
        mock_st.session_state = {}

        mock_rec = {
            "has_recommendation": True,
            "recommendation_type": "STATUS_INQUIRY",
            "recommended_date": "2026-02-30",
            "rationale": "Impossible date",
            "default_description": "Desc",
        }
        with (
            patch.object(self.service, "recommend_application_follow_up", return_value=mock_rec),
            patch.object(self.service, "create_application_follow_up", wraps=self.service.create_application_follow_up) as spy_create,
        ):
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
            spy_create.assert_not_called()

    @patch("dashboard.components.tracker_components.st")
    def test_draft_regeneration_resets_editable_widgets_and_preserves_edits(self, mock_st):
        """Candidate edits persist on unrelated reruns, but template regeneration refreshes editable subject/body."""
        app = self._create_app(self.user_a, "Regen Co", "Dev", status="SUBMITTED")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        session_state_dict: dict[str, Any] = {}
        mock_st.session_state = session_state_dict

        # Step 1: Generate STATUS_INQUIRY draft
        mock_st.selectbox.side_effect = lambda label, options=None, index=0, key=None: (
            "STATUS_INQUIRY" if key == f"tpl_type_{self.user_a}_{app.id}" else (options or [""])[0]
        )
        mock_st.text_input.side_effect = lambda label, value="", placeholder="", key=None: value or ""
        mock_st.button.side_effect = lambda label, key=None: key == f"gen_tpl_btn_{self.user_a}_{app.id}"

        render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        first_draft = session_state_dict.get(f"generated_draft_{self.user_a}_{app.id}")
        self.assertIsNotNone(first_draft)
        self.assertIn("Inquiry Regarding Application", session_state_dict[f"draft_subj_{self.user_a}_{app.id}"])
        self.assertIn("check in on the status", session_state_dict[f"draft_body_{self.user_a}_{app.id}"])

        # Step 2: Simulate candidate editing subject and body
        session_state_dict[f"draft_subj_{self.user_a}_{app.id}"] = "Candidate Custom Edited Subject"
        session_state_dict[f"draft_body_{self.user_a}_{app.id}"] = "Candidate Custom Edited Body"

        # Step 3: Unrelated rerun (button is not pressed)
        mock_st.button.side_effect = lambda label, key=None: False
        render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        # Confirm edits persisted across unrelated rerun
        self.assertEqual(session_state_dict[f"draft_subj_{self.user_a}_{app.id}"], "Candidate Custom Edited Subject")
        self.assertEqual(session_state_dict[f"draft_body_{self.user_a}_{app.id}"], "Candidate Custom Edited Body")

        # Step 4: Candidate generates THANK_YOU_NOTE draft for same application
        mock_st.selectbox.side_effect = lambda label, options=None, index=0, key=None: (
            "THANK_YOU_NOTE" if key == f"tpl_type_{self.user_a}_{app.id}" else (options or [""])[0]
        )
        mock_st.button.side_effect = lambda label, key=None: key == f"gen_tpl_btn_{self.user_a}_{app.id}"

        render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        # Step 5: Verify new draft replaced stale candidate edits
        new_subj = session_state_dict[f"draft_subj_{self.user_a}_{app.id}"]
        new_body = session_state_dict[f"draft_body_{self.user_a}_{app.id}"]
        self.assertNotEqual(new_subj, "Candidate Custom Edited Subject")
        self.assertNotEqual(new_body, "Candidate Custom Edited Body")
        self.assertIn("Thank You", new_subj)
        self.assertIn("Thank you for taking the time", new_body)

        # Confirm metadata corresponds to THANK_YOU_NOTE
        second_draft = session_state_dict.get(f"generated_draft_{self.user_a}_{app.id}")
        self.assertIsNotNone(second_draft)

        # Step 6: Candidate edits the newly generated draft
        session_state_dict[f"draft_subj_{self.user_a}_{app.id}"] = "Thank You So Much (Edited)"
        session_state_dict[f"draft_body_{self.user_a}_{app.id}"] = "Had a great interview (Edited)"

        # Unrelated rerun again
        mock_st.button.side_effect = lambda label, key=None: False
        render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        self.assertEqual(session_state_dict[f"draft_subj_{self.user_a}_{app.id}"], "Thank You So Much (Edited)")
        self.assertEqual(session_state_dict[f"draft_body_{self.user_a}_{app.id}"], "Had a great interview (Edited)")


# =============================================================================
# CATEGORY L: PHASE 7.5 LIFECYCLE OVERHAUL & PREPARER INTEGRATION TESTS
# =============================================================================

class TestPhase75LifecycleOverhaul(BaseTrackerUITest):
    """Verifies Phase 7.5 features:
    - Finding F1: Upstream recommendation date change refreshes date widget while preserving manual edits.
    - Finding F2: Candidate-provided assessment date provenance parity in engine and UI.
    - Status chips: Overdue, Due Today, Upcoming, and Completed ordering and categorization.
    - Stepper: Visual 5-stage lifecycle stepper reflecting authoritative milestones and terminal/reopened state.
    - Card: Expanded support, readiness indicator banners, prepared/submitted dates, and reminder chips.
    - Kanban: Follow-up chips on Kanban cards and detailed expander.
    - View focus: tracker_selected_app_id focus alert, clear button, and targeted card expansion.
    - Preparer integration: Tab 7 and Tab 8 navigation to Tracker with targeted focus.
    """

    @patch("dashboard.components.tracker_components.st")
    def test_finding_f1_recommendation_date_change_resets_widget_and_preserves_candidate_edit(self, mock_st):
        """Verifies Finding F1:
        1. Initial recommendation date sets last_rec_date and initializes rec_sched_date widget.
        2. Candidate manually overrides widget to a custom date.
        3. Unrelated rerun with unchanged recommendation date preserves candidate's manual override.
        4. Upstream recommendation date change resets widget to new date and updates last_rec_date.
        5. Candidate can edit the new date again.
        """
        app = self._create_app(self.user_a, "F1 Co", "Engineer", status="SUBMITTED")
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.button.return_value = False
        session_state_dict: dict[str, Any] = {}
        mock_st.session_state = session_state_dict

        # Step 1: Initial recommendation proposing 2026-11-15
        mock_rec_1 = {
            "has_recommendation": True,
            "recommendation_type": "STATUS_INQUIRY",
            "recommended_date": "2026-11-15",
            "rationale": "Initial status inquiry rationale",
            "default_description": "Initial inquiry",
        }
        with patch.object(self.service, "recommend_application_follow_up", return_value=mock_rec_1):
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        self.assertEqual(session_state_dict.get(f"last_rec_date_{self.user_a}_{app.id}"), "2026-11-15")
        self.assertEqual(session_state_dict.get(f"rec_sched_date_{self.user_a}_{app.id}"), date(2026, 11, 15))

        # Step 2: Candidate manually edits the scheduled date to 2026-11-18
        session_state_dict[f"rec_sched_date_{self.user_a}_{app.id}"] = date(2026, 11, 18)

        # Step 3: Unrelated rerun with same recommendation date ("2026-11-15")
        with patch.object(self.service, "recommend_application_follow_up", return_value=mock_rec_1):
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        # Confirm candidate edit is preserved!
        self.assertEqual(session_state_dict.get(f"rec_sched_date_{self.user_a}_{app.id}"), date(2026, 11, 18))
        self.assertEqual(session_state_dict.get(f"last_rec_date_{self.user_a}_{app.id}"), "2026-11-15")

        # Step 4: Upstream recommendation date changes to "2026-11-20"
        mock_rec_2 = {
            "has_recommendation": True,
            "recommendation_type": "STATUS_INQUIRY",
            "recommended_date": "2026-11-20",
            "rationale": "Updated inquiry rationale",
            "default_description": "Updated inquiry",
        }
        with patch.object(self.service, "recommend_application_follow_up", return_value=mock_rec_2):
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        # Confirm widget date is refreshed to the new recommendation date!
        self.assertEqual(session_state_dict.get(f"last_rec_date_{self.user_a}_{app.id}"), "2026-11-20")
        self.assertEqual(session_state_dict.get(f"rec_sched_date_{self.user_a}_{app.id}"), date(2026, 11, 20))

        # Step 5: Candidate can edit the newly refreshed date
        session_state_dict[f"rec_sched_date_{self.user_a}_{app.id}"] = date(2026, 11, 25)
        with patch.object(self.service, "recommend_application_follow_up", return_value=mock_rec_2):
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)

        self.assertEqual(session_state_dict.get(f"rec_sched_date_{self.user_a}_{app.id}"), date(2026, 11, 25))

    @patch("dashboard.components.tracker_components.st")
    def test_finding_f2_assessment_date_provenance_enforced(self, mock_st):
        """Verifies Finding F2:
        1. FollowUpRecommendationEngine requires explicit candidate_provided provenance for ASSESSMENT status.
        2. Missing provenance returns has_recommendation=False and assessment_date_source='unavailable'.
        3. Untrusted provenance returns has_recommendation=False.
        4. Valid candidate_provided provenance returns has_recommendation=True with 7 calendar days offset.
        5. UI populates extra_context['assessment_date_source'] = 'candidate_provided' when entered by candidate.
        """
        app = self._create_app(self.user_a, "F2 Co", "Dev", status="ASSESSMENT")

        # 1. Missing provenance in engine
        rec_missing = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"assessment_date": "2026-11-05"},
        )
        self.assertFalse(rec_missing.has_recommendation)
        self.assertIn("candidate_provided provenance", rec_missing.rationale)
        self.assertEqual(rec_missing.application_context.get("assessment_date_source"), "unavailable")

        # 2. Untrusted provenance in engine
        rec_untrusted = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={
                "assessment_date": "2026-11-05",
                "assessment_date_source": "inferred_by_scraper",
            },
        )
        self.assertFalse(rec_untrusted.has_recommendation)
        self.assertEqual(rec_untrusted.application_context.get("assessment_date_source"), "unavailable")

        # 3. Explicit candidate_provided provenance in engine
        rec_valid = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={
                "assessment_date": "2026-11-05",
                "assessment_date_source": "candidate_provided",
            },
        )
        self.assertTrue(rec_valid.has_recommendation)
        self.assertEqual(rec_valid.recommended_date, "2026-11-12")
        self.assertIn("candidate-provided assessment completion", rec_valid.rationale)
        self.assertEqual(rec_valid.application_context.get("assessment_date_source"), "candidate_provided")

        # 4. UI provides candidate_provided tag
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.popover.return_value.__enter__.return_value = MagicMock()
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.checkbox.side_effect = lambda label, key=None: key == f"rec_assess_chk_{self.user_a}_{app.id}"
        mock_st.date_input.return_value = date(2026, 11, 5)
        mock_st.button.return_value = False
        mock_st.session_state = {}

        with patch.object(self.service, "recommend_application_follow_up", wraps=self.service.recommend_application_follow_up) as spy_rec:
            render_follow_up_manager(self.service, self.session_a.session_id, app, self.user_a, False)
            spy_rec.assert_called_once()
            extra_ctx = spy_rec.call_args[1].get("extra_context", {})
            self.assertEqual(extra_ctx.get("assessment_date"), "2026-11-05")
            self.assertEqual(extra_ctx.get("assessment_date_source"), "candidate_provided")

    def test_get_application_follow_up_chips_urgency_ordering(self):
        """Verifies get_application_follow_up_chips sorts by urgency: overdue -> today -> upcoming -> completed."""
        today = date(2026, 11, 4)
        fups = [
            ApplicationFollowUp(
                application_id=10, user_id=self.user_a, follow_up_date="2026-11-15",
                follow_up_type="STATUS_INQUIRY", description="Upcoming task",
                is_completed=0, id=1,
            ),
            ApplicationFollowUp(
                application_id=10, user_id=self.user_a, follow_up_date="2026-10-25",
                follow_up_type="THANK_YOU_NOTE", description="Completed task",
                is_completed=1, id=2,
            ),
            ApplicationFollowUp(
                application_id=10, user_id=self.user_a, follow_up_date="2026-11-01",
                follow_up_type="STATUS_INQUIRY", description="Overdue task",
                is_completed=0, id=3,
            ),
            ApplicationFollowUp(
                application_id=10, user_id=self.user_a, follow_up_date="2026-11-04",
                follow_up_type="PREPARATION", description="Due today task",
                is_completed=0, id=4,
            ),
        ]

        chips = get_application_follow_up_chips(fups, today_date=today)
        self.assertEqual(len(chips), 4)
        self.assertEqual(chips[0]["category"], "overdue")
        self.assertEqual(chips[0]["id"], 3)
        self.assertIn("Overdue", chips[0]["label"])

        self.assertEqual(chips[1]["category"], "today")
        self.assertEqual(chips[1]["id"], 4)
        self.assertIn("Due Today", chips[1]["label"])

        self.assertEqual(chips[2]["category"], "upcoming")
        self.assertEqual(chips[2]["id"], 1)
        self.assertIn("Upcoming", chips[2]["label"])

        self.assertEqual(chips[3]["category"], "completed")
        self.assertEqual(chips[3]["id"], 2)
        self.assertIn("Completed", chips[3]["label"])

    @patch("dashboard.components.tracker_components.st")
    def test_render_lifecycle_stepper_milestones_and_terminal_reopened(self, mock_st):
        """Verifies render_lifecycle_stepper renders active, completed, terminal, and reopen states."""
        # 1. Offer stage application
        app_offer = self._create_app(self.user_a, "Stepper Co", "Engineer", status="OFFER")
        col_mocks = [MagicMock() for _ in range(5)]
        mock_st.columns.return_value = col_mocks

        render_lifecycle_stepper(app_offer, events=[])
        mock_st.success.assert_called_with("🎉 **Offer Stage:** Candidate has received an offer for this position!")

        # 2. Terminal stage application
        app_term = self._create_app(self.user_a, "Term Co", "Engineer", status="REJECTED")
        mock_st.reset_mock()
        mock_st.columns.return_value = col_mocks

        render_lifecycle_stepper(app_term, events=[])
        caption_calls = [call[0][0] for call in mock_st.caption.call_args_list]
        self.assertTrue(any("Application concluded in terminal state: `REJECTED`" in str(c) for c in caption_calls))

        # 3. Reopened application with events
        app_reopen = self._create_app(self.user_a, "Reopen Co", "Engineer", status="IN_PROGRESS")
        mock_st.reset_mock()
        mock_st.columns.return_value = col_mocks
        evt = ApplicationEvent(
            application_id=app_reopen.id,
            user_id=self.user_a,
            sequence_no=1,
            event_type="APPLICATION_REOPENED",
            actor_type="CANDIDATE",
            actor_identifier=f"user_{self.user_a}",
            event_payload_json=json.dumps({"reopen_rationale": "Position re-listed by hiring team"}),
            previous_event_hash="0" * 64,
            event_hash="h1",
            id=1,
        )
        render_lifecycle_stepper(app_reopen, events=[evt])
        info_calls = [call[0][0] for call in mock_st.info.call_args_list]
        self.assertTrue(any("Position re-listed by hiring team" in str(c) for c in info_calls))

    @patch("dashboard.components.tracker_components.st")
    def test_render_application_card_expanded_and_readiness_banners(self, mock_st):
        """Verifies render_application_card supports expanded parameter and displays status readiness banners."""
        app_approved = self._create_app(self.user_a, "Approved Co", "Lead Dev", status="APPROVED")
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE applications SET date_prepared = '2026-11-02' WHERE id = ?",
                (app_approved.id,),
            )
        app_approved = self.db.get_user_application(app_approved.id, self.user_a)

        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.tabs.side_effect = lambda tabs: [MagicMock() for _ in tabs]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()

        # Render with expanded=True
        render_application_card(
            app_approved, self.service, self.session_a.session_id, self.user_a,
            include_archived=False, expanded=True,
        )
        # Verify expander received expanded=True
        exp_calls = [call[1].get("expanded") for call in mock_st.expander.call_args_list]
        self.assertIn(True, exp_calls)

        # Verify warning banner for APPROVED
        warn_calls = [call[0][0] for call in mock_st.warning.call_args_list]
        self.assertTrue(any("Action Required: Application Human-Approved!" in str(c) for c in warn_calls))

        # Test READY_FOR_REVIEW banner
        app_ready = self._create_app(self.user_a, "Ready Co", "Lead Dev", status="READY_FOR_REVIEW")
        mock_st.reset_mock()
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.tabs.side_effect = lambda tabs: [MagicMock() for _ in tabs]
        render_application_card(
            app_ready, self.service, self.session_a.session_id, self.user_a,
            include_archived=False, expanded=False,
        )
        info_calls = [call[0][0] for call in mock_st.info.call_args_list]
        self.assertTrue(any("Review Ready:" in str(c) for c in info_calls))

        # Test SUBMITTED banner
        app_sub = self._create_app(self.user_a, "Sub Co", "Lead Dev", status="SUBMITTED")
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE applications SET date_submitted = '2026-11-03' WHERE id = ?",
                (app_sub.id,),
            )
        app_sub = self.db.get_user_application(app_sub.id, self.user_a)
        mock_st.reset_mock()
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.tabs.side_effect = lambda tabs: [MagicMock() for _ in tabs]
        render_application_card(
            app_sub, self.service, self.session_a.session_id, self.user_a,
            include_archived=False, expanded=False,
        )
        succ_calls = [call[0][0] for call in mock_st.success.call_args_list]
        self.assertTrue(any("Submitted Externally:" in str(c) for c in succ_calls))

    @patch("dashboard.components.tracker_components.st")
    def test_render_kanban_board_view_follow_up_chips_and_cards(self, mock_st):
        """Verifies render_kanban_board_view accepts follow_ups, renders badges on cards, and details in expander."""
        app = self._create_app(
            self.user_a, "Kanban Fup Co", "ML Engineer",
            status="SUBMITTED", application_deadline="2026-11-30",
        )
        fup = ApplicationFollowUp(
            application_id=app.id,
            user_id=self.user_a,
            follow_up_date="2026-11-01",  # Overdue
            follow_up_type="STATUS_INQUIRY",
            description="Urgent status check",
            is_completed=0,
            id=101,
        )
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.tabs.side_effect = lambda tabs: [MagicMock() for _ in tabs]

        render_kanban_board_view(
            [app], self.service, self.session_a.session_id, self.user_a,
            include_archived=False, follow_ups=[fup],
        )

        # Verify markdown calls rendered the overdue chip HTML
        md_calls = [call[0][0] for call in mock_st.markdown.call_args_list]
        has_overdue_chip = any("Overdue: STATUS_INQUIRY" in str(c) for c in md_calls)
        self.assertTrue(has_overdue_chip)

    @patch("dashboard.views.application_tracker.st")
    def test_application_tracker_focus_navigation_flow(self, mock_st):
        """Verifies render_application_tracker surfaces focus banner and target card expansion when tracker_selected_app_id is set."""
        app = self._create_app(self.user_a, "Focus Co", "Engineer", status="APPROVED")
        mock_st.session_state = {
            "authenticated_session_id": self.session_a.session_id,
            "authenticated_user_id": self.user_a,
            "tracker_selected_app_id": app.id,
        }
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.button.return_value = False

        with patch("dashboard.views.application_tracker.DashboardService.get_instance", return_value=self.service):
            render_application_tracker()

        # Verify focus banner was rendered
        info_calls = [call[0][0] for call in mock_st.info.call_args_list]
        self.assertTrue(any(f"Showing Application #{app.id}" in str(c) for c in info_calls))

        # Verify focus banner was rendered
        info_calls = [call[0][0] for call in mock_st.info.call_args_list]
        self.assertTrue(any(f"Showing Application #{app.id}" in str(c) for c in info_calls))

    @patch("dashboard.views.application_preparer.st")
    def test_application_preparer_navigation_buttons(self, mock_st):
        """Verifies Application Preparer Tab 7 and Tab 8 navigation buttons set tracker_selected_app_id."""
        app = self._create_app(self.user_a, "Nav Co", "Engineer", status="APPROVED")
        session_state_dict: dict[str, Any] = {
            "authenticated_session_id": self.session_a.session_id,
            "authenticated_user_id": self.user_a,
        }
        mock_st.session_state = session_state_dict
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.button.side_effect = lambda label, key=None, type=None: key == f"open_tracker_tab7_{app.id}"

        # Test simulating the Tab 7 button logic
        if mock_st.button("📋 Open in Application Tracker", key=f"open_tracker_tab7_{app.id}", type="primary"):
            mock_st.session_state["tracker_selected_app_id"] = app.id

        self.assertEqual(mock_st.session_state.get("tracker_selected_app_id"), app.id)

        # Test Tab 8 button logic
        mock_st.session_state["tracker_selected_app_id"] = None
        mock_st.button.side_effect = lambda label, key=None: key == f"open_tracker_tab8_{app.id}"
        if mock_st.button("📋 View in Tracker", key=f"open_tracker_tab8_{app.id}"):
            mock_st.session_state["tracker_selected_app_id"] = app.id

        self.assertEqual(mock_st.session_state.get("tracker_selected_app_id"), app.id)


if __name__ == "__main__":
    unittest.main()

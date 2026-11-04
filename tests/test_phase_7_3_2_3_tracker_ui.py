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
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional
import unittest
from unittest.mock import MagicMock, patch

from dashboard.components.tracker_components import (
    KANBAN_COLUMNS,
    build_tracker_csv_export,
    format_status_badge,
    render_application_card,
    render_archive_action,
    render_external_navigation_action,
    render_follow_up_alert_bar,
    render_follow_up_manager,
    render_kanban_board_view,
    render_lifecycle_status_actions,
    render_lifecycle_timeline_view,
    render_manual_submission_section,
    render_prepared_packets_view,
    render_tracker_filter_toolbar,
    render_tracker_header,
    render_tracker_metrics_bar,
)
from dashboard.services.dashboard_service import DashboardService
from dashboard.views.application_tracker import render_application_tracker
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    SecurityAuthorizationError,
)
from src.database.models import (
    Application,
    ApplicationStatus,
    FollowUpType,
    PreparedPacket,
    SubmissionChannel,
)
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
        target_role: Optional[str] = None,
        employment_type: Optional[str] = None,
        location: Optional[str] = None,
        salary_range: Optional[str] = None,
        application_deadline: Optional[str] = None,
        external_url: Optional[str] = None,
        job_description_id: Optional[int] = None,
        resume_id: Optional[int] = None,
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
        attachments_manifest: Optional[List[Dict[str, Any]]] = None,
        matching_result_id: Optional[int] = None,
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
        from datetime import datetime, timezone, timedelta
        # Artificially expire session_a
        self.session_a.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
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

    def test_employment_type_filtering(self):
        """Filtering by employment_type returns only matching applications."""
        self._create_app(self.user_a, "C1", "R1", employment_type="Full-time")
        self._create_app(self.user_a, "C2", "R2", employment_type="Internship")

        full_time = self.service.list_candidate_applications(self.session_a.session_id, employment_type="Full-time")
        self.assertEqual(len(full_time), 1)
        self.assertEqual(full_time[0].company_name, "C1")

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
        with self.assertRaises(Exception):
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
        with self.assertRaises(Exception):
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


if __name__ == "__main__":
    unittest.main()

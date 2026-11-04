"""Comprehensive Unit, Integration & Security Test Suite for Phase 7.4.1:
Follow-Up Engine Backend Architecture, Atomic Auditing & Service APIs.

Covers:
1. Database & CRUD operations for candidate follow-ups
2. Atomic database transaction auditing & failure rollbacks
3. Follow-up recommendation engine heuristics (SUBMITTED, INTERVIEW, ASSESSMENT, OFFER)
4. Zero-hallucination message template drafting with verified context
5. Service-layer security, session resolution, and IDOR protection
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ApplicationNotFoundError,
    CrossUserAccessError,
    InvalidSessionError,
    SessionExpiredError,
    ValidationError,
)
from src.database.models import Application, ApplicationFollowUp, ApplicationStatus, FollowUpType
from src.lifecycle.follow_up_engine import (
    FollowUpRecommendationEngine,
    FollowUpTemplateGenerator,
)
from src.security.session_manager import SessionManager


class BaseFollowUpTest(unittest.TestCase):
    """Base fixture setting up an isolated SQLite database, services, and two test candidates."""

    def setUp(self):
        self.temp_db_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_db_dir.name) / "test_follow_ups.db"
        self.db = DatabaseManager(db_path=str(self.db_path))

        self.temp_storage_dir = tempfile.TemporaryDirectory()
        self.storage_base = Path(self.temp_storage_dir.name)

        self.service = DashboardService(
            db_manager=self.db,
            storage_base_dir=self.storage_base,
        )

        SessionManager._instance = None
        self.session_mgr = SessionManager.get_instance()

        # Seed two candidate users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'alice@example.com', 'h1', 's1', 'Alice Walker')"
            )
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'bob@example.com', 'h2', 's2', 'Bob Smith')"
            )

        self.user_a = 1
        self.user_b = 2

        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="cand_a",
            candidate_name="Alice Walker",
            user_id=self.user_a,
        )
        self.session_b = self.session_mgr.authenticate_candidate(
            candidate_id="cand_b",
            candidate_name="Bob Smith",
            user_id=self.user_b,
        )

        # Seed candidate profile for Alice
        self.db.save_user_candidate_profile(
            self.user_a,
            {
                "personal_information": {
                    "full_name": "Alice Walker",
                    "email": "alice@example.com",
                },
                "technical_skills": ["Python", "FastAPI", "SQL"],
            },
        )

        # Create an application for Alice
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO applications (
                    id, user_id, company_name, job_title, status,
                    date_submitted, is_archived, notes
                ) VALUES (101, 1, 'DeepMind Technologies', 'AI Research Scientist',
                          'SUBMITTED', '2026-11-02T10:00:00Z', 0, 'First round application')
                """
            )
            cursor.execute(
                """
                INSERT INTO applications (
                    id, user_id, company_name, job_title, status,
                    is_archived
                ) VALUES (201, 2, 'Stripe', 'Backend Engineer', 'IN_PROGRESS', 0)
                """
            )

        self.app_a = self.db.get_user_application(101, self.user_a)
        self.app_b = self.db.get_user_application(201, self.user_b)

    def tearDown(self):
        SessionManager._instance = None
        self.temp_db_dir.cleanup()
        self.temp_storage_dir.cleanup()


# =============================================================================
# 1. DATABASE AND CRUD OPERATIONS
# =============================================================================

class TestFollowUpDatabaseCRUD(BaseFollowUpTest):
    """Tests core follow-up persistence, querying, completion, and deletion."""

    def test_create_follow_up_success(self):
        fup = self.db.create_application_follow_up(
            application_id=self.app_a.id,
            user_id=self.user_a,
            follow_up_date="2026-11-15",
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            description="Follow up on AI Research Scientist submission",
        )
        self.assertIsNotNone(fup.id)
        self.assertEqual(fup.application_id, self.app_a.id)
        self.assertEqual(fup.user_id, self.user_a)
        self.assertEqual(fup.follow_up_date, "2026-11-15")
        self.assertEqual(fup.follow_up_type, "STATUS_INQUIRY")
        self.assertEqual(fup.description, "Follow up on AI Research Scientist submission")
        self.assertFalse(fup.is_completed)
        self.assertIsNone(fup.completed_at)

    def test_create_follow_up_empty_description_rejected(self):
        with self.assertRaises(ValidationError):
            self.db.create_application_follow_up(
                application_id=self.app_a.id,
                user_id=self.user_a,
                follow_up_date="2026-11-15",
                follow_up_type=FollowUpType.STATUS_INQUIRY.value,
                description="   ",
            )

    def test_create_follow_up_invalid_type_rejected(self):
        with self.assertRaises(ValidationError):
            self.db.create_application_follow_up(
                application_id=self.app_a.id,
                user_id=self.user_a,
                follow_up_date="2026-11-15",
                follow_up_type="INVALID_TYPE",
                description="Check status",
            )

    def test_create_follow_up_invalid_date_format_rejected(self):
        with self.assertRaises(ValidationError):
            self.db.create_application_follow_up(
                application_id=self.app_a.id,
                user_id=self.user_a,
                follow_up_date="15-11-2026",  # invalid format
                follow_up_type=FollowUpType.STATUS_INQUIRY.value,
                description="Check status",
            )

    def test_create_follow_up_nonexistent_application_rejected(self):
        with self.assertRaises(ApplicationNotFoundError):
            self.db.create_application_follow_up(
                application_id=9999,
                user_id=self.user_a,
                follow_up_date="2026-11-15",
                follow_up_type=FollowUpType.STATUS_INQUIRY.value,
                description="Check status",
            )

    def test_get_follow_up_success(self):
        created = self.db.create_application_follow_up(
            application_id=self.app_a.id,
            user_id=self.user_a,
            follow_up_date="2026-11-15",
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            description="Check status",
        )
        fetched = self.db.get_application_follow_up(created.id, self.user_a)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.id, created.id)
        self.assertEqual(fetched.description, "Check status")

    def test_get_follow_up_not_found_returns_none(self):
        self.assertIsNone(self.db.get_application_follow_up(9999, self.user_a))

    def test_get_follow_up_cross_user_rejected(self):
        created = self.db.create_application_follow_up(
            application_id=self.app_a.id,
            user_id=self.user_a,
            follow_up_date="2026-11-15",
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            description="Alice reminder",
        )
        with self.assertRaises(CrossUserAccessError):
            self.db.get_application_follow_up(created.id, self.user_b)

    def test_list_follow_ups_filters(self):
        f1 = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-10", FollowUpType.STATUS_INQUIRY.value, "Rem 1"
        )
        f2 = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-12", FollowUpType.THANK_YOU_NOTE.value, "Rem 2"
        )
        self.db.complete_application_follow_up(f1.id, self.user_a, "Done")

        # List all
        all_f = self.db.list_application_follow_ups(self.user_a, application_id=self.app_a.id)
        self.assertEqual(len(all_f), 2)

        # List pending
        pending = self.db.list_application_follow_ups(
            self.user_a, application_id=self.app_a.id, is_completed=False
        )
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].id, f2.id)

        # List completed
        completed = self.db.list_application_follow_ups(
            self.user_a, application_id=self.app_a.id, is_completed=True
        )
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].id, f1.id)

    def test_list_follow_ups_archive_scoping(self):
        f = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-10", FollowUpType.STATUS_INQUIRY.value, "Archivable"
        )
        # Archive application
        self.db.archive_user_application(self.app_a.id, self.user_a, "Test archive")

        # Excluded by default
        default_list = self.db.list_application_follow_ups(self.user_a)
        self.assertEqual(len(default_list), 0)

        # Included when requested
        archived_list = self.db.list_application_follow_ups(self.user_a, include_archived=True)
        self.assertEqual(len(archived_list), 1)
        self.assertEqual(archived_list[0].id, f.id)

    def test_complete_follow_up_success(self):
        created = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-10", FollowUpType.STATUS_INQUIRY.value, "Status check"
        )
        completed = self.db.complete_application_follow_up(
            created.id, self.user_a, outcome_notes="Recruiter replied: Screen scheduled"
        )
        self.assertTrue(completed.is_completed)
        self.assertIsNotNone(completed.completed_at)
        self.assertEqual(completed.outcome_notes, "Recruiter replied: Screen scheduled")

    def test_complete_follow_up_not_found(self):
        with self.assertRaises(ValidationError):
            self.db.complete_application_follow_up(9999, self.user_a)

    def test_complete_follow_up_cross_user_rejected(self):
        created = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-10", FollowUpType.STATUS_INQUIRY.value, "Alice rem"
        )
        with self.assertRaises(CrossUserAccessError):
            self.db.complete_application_follow_up(created.id, self.user_b)

    def test_delete_follow_up_success(self):
        created = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-10", FollowUpType.STATUS_INQUIRY.value, "To delete"
        )
        res = self.db.delete_application_follow_up(created.id, self.user_a)
        self.assertTrue(res)
        self.assertIsNone(self.db.get_application_follow_up(created.id, self.user_a))

    def test_delete_follow_up_cross_user_rejected(self):
        created = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-10", FollowUpType.STATUS_INQUIRY.value, "Alice rem"
        )
        with self.assertRaises(CrossUserAccessError):
            self.db.delete_application_follow_up(created.id, self.user_b)


# =============================================================================
# 2. ATOMIC AUDITING & HASH-CHAIN INTEGRITY
# =============================================================================

class TestFollowUpAtomicAuditing(BaseFollowUpTest):
    """Tests that follow-up lifecycle mutations emit atomic events in application_events."""

    def test_create_follow_up_emits_scheduled_event_atomically(self):
        fup = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-15", FollowUpType.STATUS_INQUIRY.value, "Atomic check"
        )
        events = self.db.get_application_events(self.app_a.id, self.user_a)
        sched_events = [e for e in events if e.event_type == "FOLLOW_UP_SCHEDULED"]
        self.assertEqual(len(sched_events), 1)

        ev = sched_events[0]
        payload = json.loads(ev.event_payload_json)
        self.assertEqual(payload["follow_up_id"], fup.id)
        self.assertEqual(payload["follow_up_type"], "STATUS_INQUIRY")
        self.assertEqual(payload["follow_up_date"], "2026-11-15")
        self.assertEqual(payload["description"], "Atomic check")

    def test_complete_follow_up_emits_completed_event_atomically(self):
        fup = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-15", FollowUpType.STATUS_INQUIRY.value, "To complete"
        )
        self.db.complete_application_follow_up(fup.id, self.user_a, outcome_notes="Interview set")

        events = self.db.get_application_events(self.app_a.id, self.user_a)
        comp_events = [e for e in events if e.event_type == "FOLLOW_UP_COMPLETED"]
        self.assertEqual(len(comp_events), 1)

        ev = comp_events[0]
        payload = json.loads(ev.event_payload_json)
        self.assertEqual(payload["follow_up_id"], fup.id)
        self.assertEqual(payload["outcome_notes"], "Interview set")

    def test_delete_follow_up_emits_deleted_event_atomically(self):
        fup = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-15", FollowUpType.STATUS_INQUIRY.value, "To delete"
        )
        self.db.delete_application_follow_up(fup.id, self.user_a)

        events = self.db.get_application_events(self.app_a.id, self.user_a)
        del_events = [e for e in events if e.event_type == "FOLLOW_UP_DELETED"]
        self.assertEqual(len(del_events), 1)

        ev = del_events[0]
        payload = json.loads(ev.event_payload_json)
        self.assertEqual(payload["follow_up_id"], fup.id)
        self.assertEqual(payload["follow_up_type"], "STATUS_INQUIRY")
        self.assertEqual(payload["description"], "To delete")

    def test_create_follow_up_rollback_on_event_failure(self):
        """If event insertion fails, the follow-up record insertion must roll back."""
        with (
            patch.object(self.db, "_insert_application_event_internal", side_effect=RuntimeError("Simulated event failure")),
            self.assertRaises(RuntimeError),
        ):
            self.db.create_application_follow_up(
                self.app_a.id, self.user_a, "2026-11-15", FollowUpType.STATUS_INQUIRY.value, "Will fail"
            )

        # Verify no orphan follow-up row was created
        reminders = self.db.list_application_follow_ups(self.user_a, application_id=self.app_a.id)
        self.assertEqual(len(reminders), 0)

    def test_complete_follow_up_rollback_on_event_failure(self):
        """If event insertion fails on completion, the completion status update must roll back."""
        fup = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-15", FollowUpType.STATUS_INQUIRY.value, "Will fail comp"
        )

        with (
            patch.object(self.db, "_insert_application_event_internal", side_effect=RuntimeError("Simulated event failure")),
            self.assertRaises(RuntimeError),
        ):
            self.db.complete_application_follow_up(fup.id, self.user_a, "Done")

        # Verify record remains uncompleted
        fup_after = self.db.get_application_follow_up(fup.id, self.user_a)
        self.assertFalse(fup_after.is_completed)
        self.assertIsNone(fup_after.completed_at)

    def test_delete_follow_up_rollback_on_event_failure(self):
        """If event insertion fails on deletion, the follow-up record deletion must roll back."""
        fup = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-15", FollowUpType.STATUS_INQUIRY.value, "Will fail delete"
        )

        with (
            patch.object(self.db, "_insert_application_event_internal", side_effect=RuntimeError("Simulated event failure")),
            self.assertRaises(RuntimeError),
        ):
            self.db.delete_application_follow_up(fup.id, self.user_a)

        # Verify record was NOT deleted
        fup_after = self.db.get_application_follow_up(fup.id, self.user_a)
        self.assertIsNotNone(fup_after)

    def test_hash_chain_remains_cryptographically_consistent_after_follow_ups(self):
        """Verifies full cryptographic timeline continuity through create, complete, delete lifecycle."""
        f1 = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-15", FollowUpType.STATUS_INQUIRY.value, "F1"
        )
        self.db.complete_application_follow_up(f1.id, self.user_a, "Note 1")
        f2 = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-20", FollowUpType.THANK_YOU_NOTE.value, "F2"
        )
        self.db.delete_application_follow_up(f2.id, self.user_a)

        is_valid, msg = self.db.verify_application_event_chain(self.app_a.id, self.user_a)
        self.assertTrue(is_valid, f"Hash chain broken: {msg}")

        # Check sequence numbers are strictly 1, 2, 3, 4
        events = self.db.get_application_events(self.app_a.id, self.user_a)
        seqs = [e.sequence_no for e in events]
        self.assertEqual(seqs, list(range(1, len(events) + 1)))


# =============================================================================
# 3. FOLLOW-UP RECOMMENDATION ENGINE
# =============================================================================

class TestFollowUpRecommendationEngine(BaseFollowUpTest):
    """Tests deterministic recommendation heuristics across application states."""

    def test_business_days_addition_skips_weekends(self):
        # Wednesday 2026-11-04
        start = date(2026, 11, 4)
        # 1 business day -> Thursday 2026-11-05
        self.assertEqual(FollowUpRecommendationEngine.add_business_days(start, 1), date(2026, 11, 5))
        # 2 business days -> Friday 2026-11-06
        self.assertEqual(FollowUpRecommendationEngine.add_business_days(start, 2), date(2026, 11, 6))
        # 3 business days -> skips Sat 7, Sun 8 -> Monday 2026-11-09
        self.assertEqual(FollowUpRecommendationEngine.add_business_days(start, 3), date(2026, 11, 9))
        # 10 business days -> Wednesday 2026-11-18 (exactly 14 calendar days)
        self.assertEqual(FollowUpRecommendationEngine.add_business_days(start, 10), date(2026, 11, 18))

    def test_submitted_recommends_status_inquiry_10_business_days(self):
        # App submitted on Monday 2026-11-02
        ref = date(2026, 11, 3)
        rec = FollowUpRecommendationEngine.recommend(
            application=self.app_a,
            existing_reminders=[],
            reference_date=ref,
            extra_context={"submission_timestamp": "2026-11-02T10:00:00Z"},
        )
        self.assertTrue(rec.has_recommendation)
        self.assertEqual(rec.recommendation_type, FollowUpType.STATUS_INQUIRY.value)
        # Monday 2026-11-02 + 10 business days = Monday 2026-11-16
        self.assertEqual(rec.recommended_date, "2026-11-16")
        self.assertIn("10 business days", rec.rationale)

    def test_submitted_suppresses_duplicate_pending_inquiry(self):
        # Existing pending reminder of same type
        existing = [
            ApplicationFollowUp(
                id=1,
                application_id=self.app_a.id,
                user_id=self.user_a,
                follow_up_date="2026-11-16",
                follow_up_type=FollowUpType.STATUS_INQUIRY.value,
                description="Existing",
                is_completed=0,
            )
        ]
        rec = FollowUpRecommendationEngine.recommend(
            application=self.app_a,
            existing_reminders=existing,
            reference_date=date(2026, 11, 3),
            extra_context={"submission_timestamp": "2026-11-02"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("already scheduled", rec.rationale)

    def test_submitted_permits_recommendation_when_previous_is_completed(self):
        # Completed reminder does not block a new recommendation
        existing = [
            ApplicationFollowUp(
                id=1,
                application_id=self.app_a.id,
                user_id=self.user_a,
                follow_up_date="2026-11-16",
                follow_up_type=FollowUpType.STATUS_INQUIRY.value,
                description="Existing completed",
                is_completed=1,
            )
        ]
        rec = FollowUpRecommendationEngine.recommend(
            application=self.app_a,
            existing_reminders=existing,
            reference_date=date(2026, 11, 3),
            extra_context={"submission_timestamp": "2026-11-02"},
        )
        self.assertTrue(rec.has_recommendation)

    def test_interview_recommends_thank_you_note_within_24_hours(self):
        app_interview = Application(
            id=102,
            user_id=self.user_a,
            company_name="Google",
            job_title="SWE",
            status=ApplicationStatus.INTERVIEW.value,
        )
        ref = date(2026, 11, 10)
        rec = FollowUpRecommendationEngine.recommend(
            application=app_interview,
            existing_reminders=[],
            reference_date=ref,
            extra_context={"interview_date": "2026-11-10"},
        )
        self.assertTrue(rec.has_recommendation)
        self.assertEqual(rec.recommendation_type, FollowUpType.THANK_YOU_NOTE.value)
        # Next calendar day
        self.assertEqual(rec.recommended_date, "2026-11-11")
        self.assertIn("24 hours", rec.rationale)

    def test_interview_missing_date_returns_no_recommendation(self):
        app_interview = Application(
            id=102,
            user_id=self.user_a,
            company_name="Google",
            job_title="SWE",
            status=ApplicationStatus.INTERVIEW.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app_interview,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={},  # no interview_date provided
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("No verified interview date", rec.rationale)

    def test_interview_past_date_returns_no_recommendation(self):
        app_interview = Application(
            id=102,
            user_id=self.user_a,
            company_name="Google",
            job_title="SWE",
            status=ApplicationStatus.INTERVIEW.value,
        )
        # Interview was 5 days ago relative to reference date
        rec = FollowUpRecommendationEngine.recommend(
            application=app_interview,
            existing_reminders=[],
            reference_date=date(2026, 11, 15),
            extra_context={"interview_date": "2026-11-10"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("window has expired", rec.rationale)

    def test_assessment_recommends_status_inquiry_7_calendar_days(self):
        app_assess = Application(
            id=103,
            user_id=self.user_a,
            company_name="Amazon",
            job_title="Data Scientist",
            status=ApplicationStatus.ASSESSMENT.value,
        )
        ref = date(2026, 11, 5)
        rec = FollowUpRecommendationEngine.recommend(
            application=app_assess,
            existing_reminders=[],
            reference_date=ref,
            extra_context={"assessment_date": "2026-11-05"},
        )
        self.assertTrue(rec.has_recommendation)
        self.assertEqual(rec.recommendation_type, FollowUpType.STATUS_INQUIRY.value)
        self.assertEqual(rec.recommended_date, "2026-11-12")
        self.assertIn("7 calendar days", rec.rationale)

    def test_offer_recommends_checkin_before_deadline(self):
        app_offer = Application(
            id=104,
            user_id=self.user_a,
            company_name="Apple",
            job_title="ML Engineer",
            status=ApplicationStatus.OFFER.value,
        )
        ref = date(2026, 11, 10)
        # Offer deadline is 2026-11-20
        rec = FollowUpRecommendationEngine.recommend(
            application=app_offer,
            existing_reminders=[],
            reference_date=ref,
            extra_context={"offer_deadline": "2026-11-20"},
        )
        self.assertTrue(rec.has_recommendation)
        self.assertEqual(rec.recommendation_type, FollowUpType.RECRUITER_CHECKIN.value)
        # Recommended 2 days before deadline: 2026-11-18
        self.assertEqual(rec.recommended_date, "2026-11-18")

    def test_offer_past_deadline_returns_no_recommendation(self):
        app_offer = Application(
            id=104,
            user_id=self.user_a,
            company_name="Apple",
            job_title="ML Engineer",
            status=ApplicationStatus.OFFER.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app_offer,
            existing_reminders=[],
            reference_date=date(2026, 11, 25),
            extra_context={"offer_deadline": "2026-11-20"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("is today or in the past", rec.rationale)

    def test_draft_status_returns_no_recommendation(self):
        app_draft = Application(
            id=105,
            user_id=self.user_a,
            company_name="Startup",
            job_title="Intern",
            status=ApplicationStatus.DRAFT.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app_draft,
            existing_reminders=[],
        )
        self.assertFalse(rec.has_recommendation)

    def test_safe_date_parsing_edge_cases(self):
        self.assertIsNone(FollowUpRecommendationEngine.parse_date_safe(None))
        self.assertIsNone(FollowUpRecommendationEngine.parse_date_safe(""))
        self.assertIsNone(FollowUpRecommendationEngine.parse_date_safe("invalid-date"))
        self.assertEqual(FollowUpRecommendationEngine.parse_date_safe(date(2026, 1, 1)), date(2026, 1, 1))
        self.assertEqual(FollowUpRecommendationEngine.parse_date_safe(datetime(2026, 1, 1, 12, 0)), date(2026, 1, 1))
        self.assertEqual(FollowUpRecommendationEngine.parse_date_safe("2026-11-04T12:30:00Z"), date(2026, 11, 4))
        self.assertEqual(FollowUpRecommendationEngine.parse_date_safe("2026-11-04"), date(2026, 11, 4))


# =============================================================================
# 4. ZERO-HALLUCINATION TEMPLATE GENERATOR
# =============================================================================

class TestFollowUpTemplateGenerator(BaseFollowUpTest):
    """Tests zero-hallucination template drafting with verified candidate facts."""

    def test_status_inquiry_template_with_verified_facts(self):
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            application=self.app_a,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={
                "recruiter_name": "Sarah Connor",
                "submission_date": "2026-11-02",
            },
        )
        self.assertEqual(tpl.template_type, "STATUS_INQUIRY")
        self.assertIn("AI Research Scientist", tpl.subject)
        self.assertIn("Alice Walker", tpl.subject)
        self.assertIn("Dear Sarah Connor,", tpl.body)
        self.assertIn("DeepMind Technologies", tpl.body)
        self.assertIn("submitted on 2026-11-02", tpl.body)
        self.assertIn("Alice Walker", tpl.body)
        self.assertTrue(tpl.context_metadata["has_verified_recruiter"])

    def test_status_inquiry_template_with_missing_contact_uses_placeholder(self):
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            application=self.app_a,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={},  # no recruiter name
        )
        self.assertIn("Dear [RECRUITER NAME],", tpl.body)
        self.assertFalse(tpl.context_metadata["has_verified_recruiter"])

    def test_thank_you_note_template_with_verified_interviewer(self):
        app_interview = Application(
            id=102,
            user_id=self.user_a,
            company_name="Google Brain",
            job_title="Research Scientist",
            status=ApplicationStatus.INTERVIEW.value,
        )
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=app_interview,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={
                "interviewer_name": "Dr. Geoffrey Hinton",
                "interview_date": "2026-11-10",
            },
        )
        self.assertIn("Dear Dr. Geoffrey Hinton,", tpl.body)
        self.assertIn("Research Scientist", tpl.subject)
        self.assertIn("Google Brain", tpl.body)
        self.assertIn("on 2026-11-10", tpl.body)
        self.assertTrue(tpl.context_metadata["has_verified_interviewer"])

    def test_thank_you_note_template_missing_interviewer_uses_placeholder(self):
        app_interview = Application(
            id=102,
            user_id=self.user_a,
            company_name="Google Brain",
            job_title="Research Scientist",
            status=ApplicationStatus.INTERVIEW.value,
        )
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=app_interview,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={},
        )
        self.assertIn("Dear [INTERVIEWER NAME],", tpl.body)
        self.assertFalse(tpl.context_metadata["has_verified_interviewer"])

    def test_recruiter_checkin_template(self):
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.RECRUITER_CHECKIN.value,
            application=self.app_a,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={"recruiter_name": "James Bond"},
        )
        self.assertIn("Dear James Bond,", tpl.body)
        self.assertIn("Touching Base Regarding AI Research Scientist", tpl.subject)
        self.assertIn("DeepMind Technologies", tpl.body)

    def test_template_unsupported_type_rejected(self):
        with self.assertRaises(ValidationError):
            FollowUpTemplateGenerator.generate(
                follow_up_type="PHONE_CALL",  # Phone calls don't use email template
                application=self.app_a,
            )


# =============================================================================
# 5. DASHBOARD SERVICE INTEGRATION & SECURITY
# =============================================================================

class TestFollowUpServiceSecurity(BaseFollowUpTest):
    """Tests service methods, session scoping, and multi-user isolation."""

    def test_service_recommend_application_follow_up_success(self):
        rec = self.service.recommend_application_follow_up(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            reference_date=date(2026, 11, 3),
        )
        self.assertTrue(rec["has_recommendation"])
        self.assertEqual(rec["recommendation_type"], FollowUpType.STATUS_INQUIRY.value)
        self.assertEqual(rec["recommended_date"], "2026-11-16")

    def test_service_recommend_missing_session_rejected(self):
        with self.assertRaises(InvalidSessionError):
            self.service.recommend_application_follow_up(
                application_id=self.app_a.id,
                session_id="",
            )

    def test_service_recommend_expired_session_rejected(self):
        # Expire session_a
        self.session_a.last_activity = datetime.now(timezone.utc) - timedelta(hours=5)
        with self.assertRaises(SessionExpiredError):
            self.service.recommend_application_follow_up(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
            )

    def test_service_recommend_cross_user_rejected(self):
        # Bob tries to access Alice's application
        with self.assertRaises((ApplicationNotFoundError, CrossUserAccessError)):
            self.service.recommend_application_follow_up(
                application_id=self.app_a.id,
                session_id=self.session_b.session_id,
            )

    def test_service_generate_template_success(self):
        res = self.service.generate_follow_up_template(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            follow_up_type="STATUS_INQUIRY",
        )
        self.assertIn("subject", res)
        self.assertIn("body", res)
        self.assertIn("Alice Walker", res["body"])
        self.assertIn("DeepMind Technologies", res["body"])

    def test_service_generate_template_cross_user_rejected(self):
        # Bob tries to generate template for Alice's application
        with self.assertRaises((ApplicationNotFoundError, CrossUserAccessError)):
            self.service.generate_follow_up_template(
                application_id=self.app_a.id,
                session_id=self.session_b.session_id,
                follow_up_type="STATUS_INQUIRY",
            )

    def test_service_generate_template_invalid_type_rejected(self):
        with self.assertRaises(ValidationError):
            self.service.generate_follow_up_template(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
                follow_up_type="INVALID_TEMPLATE",
            )


if __name__ == "__main__":
    unittest.main()

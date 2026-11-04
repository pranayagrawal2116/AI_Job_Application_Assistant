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
        self.assertEqual(payload["action"], "SCHEDULED")
        self.assertNotIn("description", payload)

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
        self.assertEqual(payload["follow_up_type"], "STATUS_INQUIRY")
        self.assertEqual(payload["follow_up_date"], "2026-11-15")
        self.assertEqual(payload["action"], "COMPLETED")
        self.assertIn("completed_at", payload)
        self.assertNotIn("outcome_notes", payload)

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
        self.assertEqual(payload["application_id"], self.app_a.id)
        self.assertEqual(payload["follow_up_type"], "STATUS_INQUIRY")
        self.assertEqual(payload["follow_up_date"], "2026-11-15")
        self.assertEqual(payload["action"], "DELETED")
        self.assertNotIn("description", payload)

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
            extra_context={"interview_date": "2026-11-10", "interview_date_source": "candidate_provided"},
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
        self.assertIn("Interview date is missing or invalid", rec.rationale)

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
            extra_context={"interview_date": "2026-11-10", "interview_date_source": "candidate_provided"},
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
        self.assertEqual(tpl.context_metadata["recruiter_name_source"], "candidate_provided")
        self.assertFalse(tpl.context_metadata["has_verified_recruiter"])

    def test_status_inquiry_template_with_missing_contact_uses_placeholder(self):
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            application=self.app_a,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={},  # no recruiter name
        )
        self.assertIn("Dear [RECRUITER NAME],", tpl.body)
        self.assertEqual(tpl.context_metadata["recruiter_name_source"], "placeholder")
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
                "interview_date_source": "candidate_provided",
            },
        )
        self.assertIn("Dear Dr. Geoffrey Hinton,", tpl.body)
        self.assertIn("Research Scientist", tpl.subject)
        self.assertIn("Google Brain", tpl.body)
        self.assertIn("on 2026-11-10", tpl.body)
        self.assertEqual(tpl.context_metadata["interviewer_name_source"], "candidate_provided")
        self.assertFalse(tpl.context_metadata["has_verified_interviewer"])

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
        self.assertEqual(tpl.context_metadata["interviewer_name_source"], "placeholder")
        self.assertFalse(tpl.context_metadata["has_verified_interviewer"])
        self.assertNotIn(" today", tpl.body)

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


# =============================================================================
# 6. PHASE 7.4.1.1 REMEDIATION: RECOMMENDATION DATE INTEGRITY
# =============================================================================

class TestFollowUpDateIntegrityRemediation(BaseFollowUpTest):
    """Tests date integrity, missing date behavior, and removal of unsafe fallbacks."""

    def test_submitted_missing_date_returns_structured_no_recommendation(self):
        """SUBMITTED without submission date returns has_recommendation=False with clear rationale."""
        app_sub_no_date = Application(
            id=301,
            user_id=self.user_a,
            company_name="Acme Corp",
            job_title="DevOps Engineer",
            status=ApplicationStatus.SUBMITTED.value,
            date_submitted=None,
            updated_at="2026-11-01T12:00:00Z",
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app_sub_no_date,
            existing_reminders=[],
            reference_date=date(2026, 11, 4),
            extra_context={},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("Authoritative submission date is missing or invalid", rec.rationale)
        self.assertIsNone(rec.recommended_date)

    def test_submitted_invalid_date_returns_structured_no_recommendation(self):
        """SUBMITTED with unparseable submission date returns has_recommendation=False."""
        app_sub_bad_date = Application(
            id=302,
            user_id=self.user_a,
            company_name="Acme Corp",
            job_title="DevOps Engineer",
            status=ApplicationStatus.SUBMITTED.value,
            date_submitted="not-a-valid-date",
            updated_at="2026-11-01T12:00:00Z",
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app_sub_bad_date,
            existing_reminders=[],
            reference_date=date(2026, 11, 4),
            extra_context={"submission_timestamp": "garbage-timestamp"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("Authoritative submission date is missing or invalid", rec.rationale)

    def test_submitted_does_not_fall_back_to_updated_at(self):
        """SUBMITTED never uses updated_at or ref_date when date_submitted is absent."""
        app = Application(
            id=303,
            user_id=self.user_a,
            company_name="Acme Corp",
            job_title="DevOps Engineer",
            status=ApplicationStatus.SUBMITTED.value,
            date_submitted=None,
            updated_at="2026-10-01T12:00:00Z",
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 4),
        )
        self.assertFalse(rec.has_recommendation)
        self.assertNotIn("2026-10", rec.rationale)

    def test_assessment_missing_date_returns_structured_no_recommendation(self):
        """ASSESSMENT without assessment date returns has_recommendation=False."""
        app_assess = Application(
            id=304,
            user_id=self.user_a,
            company_name="HackerRank Partner",
            job_title="SWE",
            status=ApplicationStatus.ASSESSMENT.value,
            updated_at="2026-11-01T12:00:00Z",
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app_assess,
            existing_reminders=[],
            reference_date=date(2026, 11, 4),
            extra_context={},  # no assessment_date provided
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("Assessment completion date is missing or invalid", rec.rationale)

    def test_assessment_invalid_date_returns_structured_no_recommendation(self):
        """ASSESSMENT with invalid date format returns has_recommendation=False."""
        app_assess = Application(
            id=305,
            user_id=self.user_a,
            company_name="HackerRank Partner",
            job_title="SWE",
            status=ApplicationStatus.ASSESSMENT.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app_assess,
            existing_reminders=[],
            reference_date=date(2026, 11, 4),
            extra_context={"assessment_date": "invalid-date-string"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("Assessment completion date is missing or invalid", rec.rationale)

    def test_assessment_does_not_fall_back_to_updated_at(self):
        """ASSESSMENT never substitutes updated_at for an assessment date."""
        app_assess = Application(
            id=306,
            user_id=self.user_a,
            company_name="HackerRank Partner",
            job_title="SWE",
            status=ApplicationStatus.ASSESSMENT.value,
            updated_at="2026-10-15T08:00:00Z",
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app_assess,
            existing_reminders=[],
            reference_date=date(2026, 11, 4),
        )
        self.assertFalse(rec.has_recommendation)

    def test_interview_invalid_date_returns_no_recommendation(self):
        """INTERVIEW with invalid date string returns has_recommendation=False."""
        app_int = Application(
            id=307,
            user_id=self.user_a,
            company_name="Meta",
            job_title="Research Scientist",
            status=ApplicationStatus.INTERVIEW.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app_int,
            existing_reminders=[],
            reference_date=date(2026, 11, 4),
            extra_context={"interview_date": "not-a-date"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("Interview date is missing or invalid", rec.rationale)

    def test_offer_missing_deadline_returns_no_recommendation(self):
        """OFFER without expiration deadline returns has_recommendation=False."""
        app_offer = Application(
            id=308,
            user_id=self.user_a,
            company_name="Anthropic",
            job_title="Alignment Engineer",
            status=ApplicationStatus.OFFER.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app_offer,
            existing_reminders=[],
            reference_date=date(2026, 11, 4),
            extra_context={},  # no deadline
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("Offer decision deadline is not recorded", rec.rationale)

    def test_offer_expired_deadline_returns_no_recommendation(self):
        """OFFER with deadline in the past returns has_recommendation=False."""
        app_offer = Application(
            id=309,
            user_id=self.user_a,
            company_name="Anthropic",
            job_title="Alignment Engineer",
            status=ApplicationStatus.OFFER.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app_offer,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"offer_deadline": "2026-11-08"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("is today or in the past", rec.rationale)


# =============================================================================
# 7. PHASE 7.4.1.1 REMEDIATION: TEMPLATE ACCURACY & FACTUALITY
# =============================================================================

class TestFollowUpTemplateAccuracyRemediation(BaseFollowUpTest):
    """Tests template truthfulness, neutral wording, and source attribution."""

    def test_thank_you_note_without_interview_date_has_no_today(self):
        """Thank-you note without interview date never asserts interview happened 'today'."""
        app_interview = Application(
            id=401,
            user_id=self.user_a,
            company_name="OpenAI",
            job_title="Research Engineer",
            status=ApplicationStatus.INTERVIEW.value,
        )
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=app_interview,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={},  # no interview_date
        )
        self.assertNotIn(" today", tpl.body)
        self.assertNotIn("today", tpl.body.lower())
        self.assertIn("Thank you for taking the time to speak with me regarding the Research Engineer position", tpl.body)

    def test_thank_you_note_neutral_wording_no_unsupported_claims(self):
        """Thank-you note removes unsupported claims about conversation enjoyment or ongoing initiatives."""
        app_interview = Application(
            id=402,
            user_id=self.user_a,
            company_name="OpenAI",
            job_title="Research Engineer",
            status=ApplicationStatus.INTERVIEW.value,
        )
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=app_interview,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={"interview_date": "2026-11-04", "interview_date_source": "candidate_provided"},
        )
        self.assertNotIn("enjoyed our conversation", tpl.body)
        self.assertNotIn("ongoing initiatives", tpl.body)
        self.assertIn("on 2026-11-04", tpl.body)
        self.assertIn("remain very interested", tpl.body)

    def test_candidate_provided_context_is_not_marked_verified(self):
        """Candidate-provided names in extra_context are labeled candidate_provided and unverified."""
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            application=self.app_a,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={"recruiter_name": "Candidate Provided Recruiter"},
        )
        self.assertEqual(tpl.context_metadata["recruiter_name_source"], "candidate_provided")
        self.assertFalse(tpl.context_metadata["has_verified_recruiter"])

    def test_missing_contact_uses_placeholders(self):
        """Missing contact names cleanly default to standard bracketed placeholders."""
        tpl_recruiter = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.RECRUITER_CHECKIN.value,
            application=self.app_a,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={},
        )
        self.assertIn("Dear [RECRUITER NAME],", tpl_recruiter.body)
        self.assertEqual(tpl_recruiter.context_metadata["recruiter_name_source"], "placeholder")

        app_int = Application(id=403, user_id=self.user_a, company_name="Co", job_title="Eng")
        tpl_interviewer = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=app_int,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={},
        )
        self.assertIn("Dear [INTERVIEWER NAME],", tpl_interviewer.body)
        self.assertEqual(tpl_interviewer.context_metadata["interviewer_name_source"], "placeholder")

    def test_recruiter_checkin_neutral_wording(self):
        """Recruiter check-in uses professional neutral inquiry without presuming promises or guidance."""
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.RECRUITER_CHECKIN.value,
            application=self.app_a,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={"recruiter_name": "John Doe"},
        )
        self.assertNotIn("ongoing guidance and support", tpl.body)
        self.assertIn("reiterate my strong interest in the role", tpl.body)
        self.assertIn("inquire whether there are any updates", tpl.body)


# =============================================================================
# 8. PHASE 7.4.1.1 REMEDIATION: ARCHIVED APPLICATION RESTRICTIONS
# =============================================================================

class TestFollowUpArchivedRestrictionRemediation(BaseFollowUpTest):
    """Tests that archived applications are rejected by service recommendation and template generators."""

    def setUp(self):
        super().setUp()
        # Create an archived application for Alice
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO applications (
                    id, user_id, company_name, job_title, status,
                    date_submitted, is_archived, notes
                ) VALUES (501, 1, 'Legacy Corp', 'Legacy Developer',
                          'SUBMITTED', '2026-11-01', 1, 'Archived position')
                """
            )
        self.archived_app = self.db.get_user_application(501, self.user_a)

    def test_owner_cannot_generate_recommendation_for_archived_application(self):
        """recommend_application_follow_up raises ValidationError for archived application."""
        with self.assertRaises(ValidationError) as ctx:
            self.service.recommend_application_follow_up(
                application_id=self.archived_app.id,
                session_id=self.session_a.session_id,
            )
        self.assertIn("archived", str(ctx.exception).lower())

    def test_owner_cannot_generate_template_for_archived_application(self):
        """generate_follow_up_template raises ValidationError for archived application."""
        with self.assertRaises(ValidationError) as ctx:
            self.service.generate_follow_up_template(
                application_id=self.archived_app.id,
                session_id=self.session_a.session_id,
                follow_up_type="STATUS_INQUIRY",
            )
        self.assertIn("archived", str(ctx.exception).lower())

    def test_active_application_succeeds(self):
        """Active (unarchived) application generates recommendation and template successfully."""
        rec = self.service.recommend_application_follow_up(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            reference_date=date(2026, 11, 3),
        )
        self.assertTrue(rec["has_recommendation"])

        tpl = self.service.generate_follow_up_template(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            follow_up_type="STATUS_INQUIRY",
        )
        self.assertIn("subject", tpl)


# =============================================================================
# 9. PHASE 7.4.1.1 REMEDIATION: AUDIT EVENT PRIVACY & MINIMIZATION
# =============================================================================

class TestFollowUpAuditPrivacyRemediation(BaseFollowUpTest):
    """Tests that sensitive candidate strings are excluded from audit event payloads."""

    def test_sensitive_string_not_in_scheduled_event_payload(self):
        """Raw reminder description is excluded from FOLLOW_UP_SCHEDULED event payload."""
        sensitive_desc = "TOP_SECRET_OFFER_DETAILS_AND_SALARY_TARGET_180K"
        fup = self.db.create_application_follow_up(
            application_id=self.app_a.id,
            user_id=self.user_a,
            follow_up_date="2026-11-20",
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            description=sensitive_desc,
        )

        # Stored description in database table is intact
        self.assertEqual(fup.description, sensitive_desc)

        # Inspect audit events in application_events
        events = self.db.get_application_events(self.app_a.id, self.user_a)
        sched_events = [e for e in events if e.event_type == "FOLLOW_UP_SCHEDULED"]
        self.assertGreaterEqual(len(sched_events), 1)

        payload = json.loads(sched_events[-1].event_payload_json)
        self.assertNotIn("description", payload)
        self.assertNotIn(sensitive_desc, sched_events[-1].event_payload_json)
        self.assertEqual(payload["follow_up_id"], fup.id)
        self.assertEqual(payload["follow_up_date"], "2026-11-20")
        self.assertEqual(payload["follow_up_type"], "STATUS_INQUIRY")
        self.assertEqual(payload["action"], "SCHEDULED")

    def test_sensitive_string_not_in_completed_event_payload(self):
        """Raw outcome notes are excluded from FOLLOW_UP_COMPLETED event payload."""
        fup = self.db.create_application_follow_up(
            application_id=self.app_a.id,
            user_id=self.user_a,
            follow_up_date="2026-11-20",
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            description="Routine follow-up",
        )
        sensitive_notes = "CONFIDENTIAL_INTERVIEW_DISCUSSIONS_REGARDING_PATENTS"
        completed = self.db.complete_application_follow_up(
            follow_up_id=fup.id,
            user_id=self.user_a,
            outcome_notes=sensitive_notes,
        )

        # Stored outcome notes in database table is intact
        self.assertEqual(completed.outcome_notes, sensitive_notes)

        events = self.db.get_application_events(self.app_a.id, self.user_a)
        comp_events = [e for e in events if e.event_type == "FOLLOW_UP_COMPLETED"]
        self.assertGreaterEqual(len(comp_events), 1)

        payload = json.loads(comp_events[-1].event_payload_json)
        self.assertNotIn("outcome_notes", payload)
        self.assertNotIn(sensitive_notes, comp_events[-1].event_payload_json)
        self.assertEqual(payload["follow_up_id"], fup.id)
        self.assertEqual(payload["action"], "COMPLETED")
        self.assertIn("completed_at", payload)

    def test_sensitive_string_not_in_deleted_event_payload(self):
        """Raw reminder description is excluded from FOLLOW_UP_DELETED event payload."""
        sensitive_desc = "PRIVATE_MEDICAL_LEAVE_SCHEDULING_NOTE"
        fup = self.db.create_application_follow_up(
            application_id=self.app_a.id,
            user_id=self.user_a,
            follow_up_date="2026-11-20",
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            description=sensitive_desc,
        )
        self.db.delete_application_follow_up(fup.id, self.user_a)

        events = self.db.get_application_events(self.app_a.id, self.user_a)
        del_events = [e for e in events if e.event_type == "FOLLOW_UP_DELETED"]
        self.assertGreaterEqual(len(del_events), 1)

        payload = json.loads(del_events[-1].event_payload_json)
        self.assertNotIn("description", payload)
        self.assertNotIn(sensitive_desc, del_events[-1].event_payload_json)
        self.assertEqual(payload["follow_up_id"], fup.id)
        self.assertEqual(payload["action"], "DELETED")

    def test_audit_hash_chain_validates_after_all_follow_up_mutations(self):
        """Cryptographic hash chain validates after creation, completion, and deletion."""
        f1 = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-21", FollowUpType.STATUS_INQUIRY.value, "Check 1"
        )
        self.db.complete_application_follow_up(f1.id, self.user_a, "Notes 1")
        f2 = self.db.create_application_follow_up(
            self.app_a.id, self.user_a, "2026-11-22", FollowUpType.THANK_YOU_NOTE.value, "Check 2"
        )
        self.db.delete_application_follow_up(f2.id, self.user_a)

        is_valid, reason = self.db.verify_application_event_chain(self.app_a.id, self.user_a)
        self.assertTrue(is_valid, f"Chain invalid: {reason}")


# =============================================================================
# 10. PHASE 7.4.1.1 REMEDIATION: CANDIDATE PROFILE EXTRACTION
# =============================================================================

class TestFollowUpCandidateProfileExtraction(BaseFollowUpTest):
    """Tests candidate profile extraction, nested structures, and account fallbacks."""

    def test_nested_profile_personal_information_full_name(self):
        """Candidate name resolved correctly from profile_data.personal_information.full_name."""
        res = self.service.generate_follow_up_template(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            follow_up_type="STATUS_INQUIRY",
        )
        self.assertIn("Alice Walker", res["body"])
        self.assertIn("Alice Walker", res["subject"])

    def test_flat_profile_full_name(self):
        """Candidate name resolved correctly from flat profile_data.full_name."""
        # Update user A's profile with flat structure
        self.db.save_user_candidate_profile(
            self.user_a,
            {"full_name": "Alicia Keys", "skills": ["Music", "AI"]},
        )
        res = self.service.generate_follow_up_template(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            follow_up_type="STATUS_INQUIRY",
        )
        self.assertIn("Alicia Keys", res["body"])
        self.assertIn("Alicia Keys", res["subject"])

    def test_missing_profile_falls_back_to_account_user_full_name(self):
        """If user has no candidate profile snapshot, falls back to account full_name."""
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (id, email, password_hash, password_salt, full_name, created_at)
                VALUES (3, 'carol@example.com', 'fakehash', 'fakesalt', 'Carol Danvers', CURRENT_TIMESTAMP)
                """
            )
            cursor.execute(
                """
                INSERT INTO applications (
                    id, user_id, company_name, job_title, status, is_archived
                ) VALUES (301, 3, 'NASA', 'Pilot', 'SUBMITTED', 0)
                """
            )
        session_carol = self.session_mgr.authenticate_candidate(
            candidate_id="cand_carol",
            candidate_name="Carol Danvers",
            user_id=3,
        )
        res = self.service.generate_follow_up_template(
            application_id=301,
            session_id=session_carol.session_id,
            follow_up_type="STATUS_INQUIRY",
        )
        self.assertIn("Carol Danvers", res["body"])
        self.assertIn("Carol Danvers", res["subject"])

    def test_missing_profile_and_missing_account_name_falls_back_to_placeholder(self):
        """If user has no candidate profile and account has empty name, uses placeholder."""
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (id, email, password_hash, password_salt, full_name, created_at)
                VALUES (4, 'anon@example.com', 'fakehash', 'fakesalt', '', CURRENT_TIMESTAMP)
                """
            )
            cursor.execute(
                """
                INSERT INTO applications (
                    id, user_id, company_name, job_title, status, is_archived
                ) VALUES (401, 4, 'Mystery Co', 'Agent', 'SUBMITTED', 0)
                """
            )
        session_anon = self.session_mgr.authenticate_candidate(
            candidate_id="cand_anon",
            candidate_name="Anonymous",
            user_id=4,
        )
        res = self.service.generate_follow_up_template(
            application_id=401,
            session_id=session_anon.session_id,
            follow_up_type="STATUS_INQUIRY",
        )
        self.assertIn("[CANDIDATE NAME]", res["body"])

    def test_malformed_profile_does_not_crash(self):
        """Malformed or minimal profile structure does not cause an exception."""
        self.db.save_user_candidate_profile(
            self.user_a,
            {"random_key": "some_value"},
        )
        res = self.service.generate_follow_up_template(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            follow_up_type="STATUS_INQUIRY",
        )
        # Should fall back to user_a's account name ("Alice Walker")
        self.assertIn("Alice Walker", res["body"])

    def test_profile_wrapper_metadata_not_leaked(self):
        """DB row wrapper columns (id, profile_hash, version) are not passed as candidate profile data."""
        profile_row = self.db.get_user_candidate_profile(self.user_a)
        self.assertIn("profile_data", profile_row)
        self.assertIn("profile_hash", profile_row)

        res = self.service.generate_follow_up_template(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            follow_up_type="STATUS_INQUIRY",
        )
        # The template subject/body should never contain the sha256 profile hash
        self.assertNotIn(profile_row["profile_hash"], res["body"])
        self.assertNotIn(profile_row["profile_hash"], res["subject"])


# =============================================================================
# 11. PHASE 7.4.1.2 REMEDIATION: FINAL DATA PROVENANCE & STRICT VALIDATION
# =============================================================================

class TestFollowUpProvenanceRemediationPhase7412(BaseFollowUpTest):
    """Tests Phase 7.4.1.2 data provenance hardening across submission, identity, and interview dates."""

    # -------------------------------------------------------------------------
    # Finding A: Remove caller-context submission-date fallback
    # -------------------------------------------------------------------------

    def test_submitted_valid_date_submitted_produces_recommendation(self):
        """Authoritative application.date_submitted produces 10 business days recommendation."""
        app = Application(
            id=601,
            user_id=self.user_a,
            company_name="DeepMind",
            job_title="Scientist",
            status=ApplicationStatus.SUBMITTED.value,
            date_submitted="2026-11-02T09:00:00Z",
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 3),
        )
        self.assertTrue(rec.has_recommendation)
        self.assertEqual(rec.recommended_date, "2026-11-16")
        self.assertIn("10 business days", rec.rationale)

    def test_submitted_missing_date_submitted_ignores_context_submission_date(self):
        """Missing date_submitted with valid extra_context['submission_date'] produces no recommendation."""
        app = Application(
            id=602,
            user_id=self.user_a,
            company_name="DeepMind",
            job_title="Scientist",
            status=ApplicationStatus.SUBMITTED.value,
            date_submitted=None,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 3),
            extra_context={"submission_date": "2026-11-02"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIsNone(rec.recommended_date)
        self.assertIn("Authoritative submission date is missing or invalid", rec.rationale)

    def test_submitted_missing_date_submitted_ignores_context_submission_timestamp(self):
        """Missing date_submitted with valid extra_context['submission_timestamp'] produces no recommendation."""
        app = Application(
            id=603,
            user_id=self.user_a,
            company_name="DeepMind",
            job_title="Scientist",
            status=ApplicationStatus.SUBMITTED.value,
            date_submitted=None,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 3),
            extra_context={"submission_timestamp": "2026-11-02T10:00:00Z"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIsNone(rec.recommended_date)
        self.assertIn("Authoritative submission date is missing or invalid", rec.rationale)

    def test_submitted_invalid_date_submitted_does_not_fall_back_to_context(self):
        """Invalid date_submitted produces no recommendation even if context has a valid date."""
        app = Application(
            id=604,
            user_id=self.user_a,
            company_name="DeepMind",
            job_title="Scientist",
            status=ApplicationStatus.SUBMITTED.value,
            date_submitted="unparseable-date",
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 3),
            extra_context={"submission_date": "2026-11-02", "submission_timestamp": "2026-11-02T10:00:00Z"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIsNone(rec.recommended_date)
        self.assertIn("Authoritative submission date is missing or invalid", rec.rationale)

    def test_submitted_never_substitutes_updated_at_or_reference_date(self):
        """Neither updated_at nor reference_date can substitute for a missing date_submitted."""
        app = Application(
            id=605,
            user_id=self.user_a,
            company_name="DeepMind",
            job_title="Scientist",
            status=ApplicationStatus.SUBMITTED.value,
            date_submitted=None,
            updated_at="2026-11-01T12:00:00Z",
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 4),
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIsNone(rec.recommended_date)

    # -------------------------------------------------------------------------
    # Finding B: Protect canonical candidate identity in templates
    # -------------------------------------------------------------------------

    def test_profile_personal_info_name_precedes_conflicting_context_name(self):
        """candidate_profile personal_information.full_name strictly overrides caller extra_context['candidate_name']."""
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            application=self.app_a,
            candidate_profile={"personal_information": {"full_name": "Alice Walker Verified"}},
            extra_context={"candidate_name": "Impersonator Name"},
            trusted_account_name="Account Name",
        )
        self.assertIn("Alice Walker Verified", tpl.body)
        self.assertIn("Alice Walker Verified", tpl.subject)
        self.assertNotIn("Impersonator Name", tpl.body)
        self.assertNotIn("Impersonator Name", tpl.subject)

    def test_flat_profile_name_precedes_conflicting_context_name(self):
        """Flat candidate_profile full_name strictly overrides caller extra_context['candidate_name']."""
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            application=self.app_a,
            candidate_profile={"full_name": "Alice Flat Verified"},
            extra_context={"candidate_name": "Fake Caller Name"},
            trusted_account_name="Account Name",
        )
        self.assertIn("Alice Flat Verified", tpl.body)
        self.assertIn("Alice Flat Verified", tpl.subject)
        self.assertNotIn("Fake Caller Name", tpl.body)
        self.assertNotIn("Fake Caller Name", tpl.subject)

    def test_account_name_fallback_precedes_untrusted_caller_context(self):
        """When profile has no usable name, trusted account name is used, ignoring caller extra_context."""
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            application=self.app_a,
            candidate_profile={"skills": ["Python"]},  # no name in profile
            extra_context={"candidate_name": "Unauthorized Alias"},
            trusted_account_name="Trusted User Name",
        )
        self.assertIn("Trusted User Name", tpl.body)
        self.assertIn("Trusted User Name", tpl.subject)
        self.assertNotIn("Unauthorized Alias", tpl.body)

    def test_placeholder_used_when_neither_profile_nor_account_has_name(self):
        """When neither profile nor account has usable name, defaults to [CANDIDATE NAME], ignoring caller context."""
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            application=self.app_a,
            candidate_profile={},
            extra_context={"candidate_name": "Injected Name"},
            trusted_account_name="",
        )
        self.assertIn("[CANDIDATE NAME]", tpl.body)
        self.assertNotIn("Injected Name", tpl.body)

    def test_whitespace_and_malformed_profile_names_handled_safely(self):
        """Whitespace-only profile names fall back to trusted account name or placeholder."""
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            application=self.app_a,
            candidate_profile={"personal_information": {"full_name": "   "}},
            trusted_account_name="Fallback Alice",
        )
        self.assertIn("Fallback Alice", tpl.body)

    def test_service_generate_template_blocks_caller_candidate_name_impersonation(self):
        """DashboardService.generate_follow_up_template prevents caller extra_context from impersonating user."""
        res = self.service.generate_follow_up_template(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            follow_up_type="STATUS_INQUIRY",
            extra_context={"candidate_name": "Malicious Impersonator"},
        )
        self.assertIn("Alice Walker", res["body"])
        self.assertNotIn("Malicious Impersonator", res["body"])

    # -------------------------------------------------------------------------
    # Finding C: Validate interview-date provenance and template formatting
    # -------------------------------------------------------------------------

    def test_interview_valid_candidate_provided_date(self):
        """Candidate-provided interview date with explicit provenance is recognized as candidate_provided."""
        app = Application(
            id=611,
            user_id=self.user_a,
            company_name="Google",
            job_title="SWE",
            status=ApplicationStatus.INTERVIEW.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"interview_date": "2026-11-10", "interview_date_source": "candidate_provided"},
        )
        self.assertTrue(rec.has_recommendation)
        self.assertEqual(rec.application_context.get("interview_date_source"), "candidate_provided")
        self.assertIn("candidate-provided", rec.rationale)

        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=app,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={"interview_date": "2026-11-10", "interview_date_source": "candidate_provided"},
        )
        self.assertIn("on 2026-11-10", tpl.body)
        self.assertEqual(tpl.context_metadata.get("interview_date_source"), "candidate_provided")
        self.assertFalse(tpl.context_metadata.get("has_verified_interviewer"))

    def test_interview_missing_date_uses_neutral_wording_and_unavailable_metadata(self):
        """Missing interview date produces no recommendation and template uses neutral wording with unavailable metadata."""
        app = Application(
            id=612,
            user_id=self.user_a,
            company_name="Google",
            job_title="SWE",
            status=ApplicationStatus.INTERVIEW.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("Interview date is missing or invalid", rec.rationale)

        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=app,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={},
        )
        self.assertNotIn(" today", tpl.body)
        self.assertNotIn(" on ", tpl.body)
        self.assertEqual(tpl.context_metadata.get("interview_date_source"), "unavailable")
        self.assertIsNone(tpl.context_metadata.get("date_referenced"))

    def test_interview_invalid_date_strings_rejected(self):
        """Invalid strings such as 'not-a-date' are rejected by both engine and template generator."""
        app = Application(
            id=613,
            user_id=self.user_a,
            company_name="Google",
            job_title="SWE",
            status=ApplicationStatus.INTERVIEW.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"interview_date": "not-a-date", "interview_date_source": "candidate_provided"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("Interview date is missing or invalid", rec.rationale)

        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=app,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={"interview_date": "not-a-date", "interview_date_source": "candidate_provided"},
        )
        self.assertNotIn("not-a-date", tpl.body)
        self.assertNotIn(" on ", tpl.body)
        self.assertEqual(tpl.context_metadata.get("interview_date_source"), "unavailable")
        self.assertIsNone(tpl.context_metadata.get("date_referenced"))

    def test_interview_impossible_date_rejected(self):
        """Impossible dates such as '2026-99-99' are rejected by both engine and template generator."""
        app = Application(
            id=614,
            user_id=self.user_a,
            company_name="Google",
            job_title="SWE",
            status=ApplicationStatus.INTERVIEW.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"interview_date": "2026-99-99", "interview_date_source": "candidate_provided"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("Interview date is missing or invalid", rec.rationale)

        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=app,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={"interview_date": "2026-99-99", "interview_date_source": "candidate_provided"},
        )
        self.assertNotIn("2026-99-99", tpl.body)
        self.assertEqual(tpl.context_metadata.get("interview_date_source"), "unavailable")
        self.assertIsNone(tpl.context_metadata.get("date_referenced"))

    def test_interview_arbitrary_malformed_timestamps_rejected(self):
        """Malformed timestamps with trailing garbage (e.g. '2026-11-10garbage') are rejected."""
        app = Application(
            id=615,
            user_id=self.user_a,
            company_name="Google",
            job_title="SWE",
            status=ApplicationStatus.INTERVIEW.value,
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"interview_date": "2026-11-10garbage", "interview_date_source": "candidate_provided"},
        )
        self.assertFalse(rec.has_recommendation)

        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=app,
            candidate_profile={"full_name": "Alice Walker"},
            extra_context={"interview_date": "2026-11-10garbage", "interview_date_source": "candidate_provided"},
        )
        self.assertNotIn("2026-11-10garbage", tpl.body)
        self.assertEqual(tpl.context_metadata.get("interview_date_source"), "unavailable")

    def test_interview_no_fallback_to_updated_at_or_current_date(self):
        """Interview recommendation never falls back to updated_at or current date."""
        app = Application(
            id=616,
            user_id=self.user_a,
            company_name="Google",
            job_title="SWE",
            status=ApplicationStatus.INTERVIEW.value,
            updated_at="2026-11-09T10:00:00Z",
        )
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIsNone(rec.recommended_date)


class TestFollowUpIdentityAndInterviewRemediationPhase7413(BaseFollowUpTest):
    """Phase 7.4.1.3 tests for Finding A (Identity Trust), Finding B (Explicit Provenance),
    and Finding C (Option B: No persisted interview date exists).
    """

    def setUp(self):
        super().setUp()

        # Seed user without a full_name in the users table
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (3, 'noname@example.com', 'h3', 's3', '')"
            )
        self.user_no_name = 3
        self.session_no_name = self.session_mgr.authenticate_candidate(
            candidate_id="cand_noname",
            candidate_name="Session Name",
            user_id=self.user_no_name,
        )

        # Create test applications in INTERVIEW status
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO applications (
                    id, user_id, company_name, job_title, status, is_archived
                ) VALUES (801, 1, 'DeepMind', 'Research Scientist', 'INTERVIEW', 0)
                """
            )
            cursor.execute(
                """
                INSERT INTO applications (
                    id, user_id, company_name, job_title, status, is_archived
                ) VALUES (802, 3, 'OpenAI', 'Member of Technical Staff', 'INTERVIEW', 0)
                """
            )
        self.app_interview_a = self.db.get_user_application(801, self.user_a)
        self.app_interview_no_name = self.db.get_user_application(802, self.user_no_name)

    # -------------------------------------------------------------------------
    # Finding A: Prevent trusted-account-name context injection
    # -------------------------------------------------------------------------

    def test_caller_supplied_trusted_account_name_with_missing_account_name_uses_placeholder(self):
        """Caller supplies _trusted_account_name when account name is missing: [CANDIDATE NAME] placeholder must be used."""
        tpl = self.service.generate_follow_up_template(
            application_id=self.app_interview_no_name.id,
            session_id=self.session_no_name.session_id,
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            client_user_id=self.user_no_name,
            extra_context={"_trusted_account_name": "Injected Attacker"},
        )
        self.assertEqual(tpl["context_metadata"]["candidate_name"], "[CANDIDATE NAME]")
        self.assertNotIn("Injected Attacker", tpl["body"])
        self.assertIn("Warm regards,\n\n[CANDIDATE NAME]", tpl["body"])

    def test_caller_supplied_trusted_account_name_conflicting_with_profile_name_profile_wins(self):
        """Caller supplies _trusted_account_name conflicting with profile: profile name wins."""
        self.db.save_user_candidate_profile(
            user_id=self.user_a,
            profile_data={"full_name": "Profile Name Alice"},
        )
        tpl = self.service.generate_follow_up_template(
            application_id=self.app_interview_a.id,
            session_id=self.session_a.session_id,
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            client_user_id=self.user_a,
            extra_context={"_trusted_account_name": "Injected Attacker"},
        )
        self.assertEqual(tpl["context_metadata"]["candidate_name"], "Profile Name Alice")
        self.assertNotIn("Injected Attacker", tpl["body"])
        self.assertIn("Profile Name Alice", tpl["body"])

    def test_caller_supplied_trusted_account_name_conflicting_with_authenticated_account_account_wins(self):
        """Caller supplies _trusted_account_name conflicting with authenticated user: authenticated account name wins."""
        tpl = self.service.generate_follow_up_template(
            application_id=self.app_interview_a.id,
            session_id=self.session_a.session_id,
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            client_user_id=self.user_a,
            extra_context={"_trusted_account_name": "Injected Attacker"},
        )
        self.assertEqual(tpl["context_metadata"]["candidate_name"], "Alice Walker")
        self.assertNotIn("Injected Attacker", tpl["body"])
        self.assertIn("Alice Walker", tpl["body"])

    def test_caller_supplies_both_candidate_name_and_trusted_account_name_neither_overrides(self):
        """Caller supplies candidate_name and _trusted_account_name: neither overrides canonical identity."""
        tpl = self.service.generate_follow_up_template(
            application_id=self.app_interview_a.id,
            session_id=self.session_a.session_id,
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            client_user_id=self.user_a,
            extra_context={
                "candidate_name": "Fake Candidate",
                "_trusted_account_name": "Injected Account",
                "trusted_account_name": "Injected Account Two",
            },
        )
        self.assertEqual(tpl["context_metadata"]["candidate_name"], "Alice Walker")
        self.assertNotIn("Fake Candidate", tpl["body"])
        self.assertNotIn("Injected Account", tpl["body"])

    def test_service_generate_template_strips_reserved_identity_keys(self):
        """Direct generator call with reserved identity keys strips them and does not leak or use them."""
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.STATUS_INQUIRY.value,
            application=self.app_interview_no_name,
            candidate_profile=None,
            extra_context={
                "_trusted_account_name": "Injected Direct",
                "trusted_account_name": "Injected Direct Two",
                "candidate_name": "Injected Direct Three",
            },
            trusted_account_name=None,
        )
        self.assertEqual(tpl.context_metadata["candidate_name"], "[CANDIDATE NAME]")
        self.assertNotIn("Injected Direct", tpl.body)

    # -------------------------------------------------------------------------
    # Finding B: Require explicit provenance for candidate-provided interview dates
    # -------------------------------------------------------------------------

    def test_interview_valid_date_with_explicit_candidate_provided_source_accepted(self):
        """Valid date with interview_date_source == 'candidate_provided' is accepted and labeled correctly."""
        rec = FollowUpRecommendationEngine.recommend(
            application=self.app_interview_a,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"interview_date": "2026-11-10", "interview_date_source": "candidate_provided"},
        )
        self.assertTrue(rec.has_recommendation)
        self.assertEqual(rec.recommended_date, "2026-11-11")
        self.assertEqual(rec.application_context.get("interview_date_source"), "candidate_provided")

        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=self.app_interview_a,
            candidate_profile={"full_name": "Alice Authenticated"},
            extra_context={"interview_date": "2026-11-10", "interview_date_source": "candidate_provided"},
        )
        self.assertIn("on 2026-11-10", tpl.body)
        self.assertEqual(tpl.context_metadata.get("interview_date_source"), "candidate_provided")
        self.assertEqual(tpl.context_metadata.get("date_referenced"), "2026-11-10")

    def test_interview_valid_date_without_source_tag_rejected_by_engine_and_template(self):
        """Valid date without interview_date_source tag is rejected by both engine and template."""
        rec = FollowUpRecommendationEngine.recommend(
            application=self.app_interview_a,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"interview_date": "2026-11-10"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIn("Interview date is missing or invalid", rec.rationale)
        self.assertEqual(rec.application_context.get("interview_date_source"), "unavailable")

        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=self.app_interview_a,
            candidate_profile={"full_name": "Alice Authenticated"},
            extra_context={"interview_date": "2026-11-10"},
        )
        self.assertNotIn("on 2026-11-10", tpl.body)
        self.assertNotIn(" on ", tpl.body)
        self.assertEqual(tpl.context_metadata.get("interview_date_source"), "unavailable")
        self.assertIsNone(tpl.context_metadata.get("date_referenced"))

    def test_interview_invalid_source_values_rejected(self):
        """Invalid or untrusted source values (e.g. 'application_record', 'verified', 'unknown') are rejected."""
        for invalid_src in ["application_record", "verified", "unknown", "untrusted", "system"]:
            rec = FollowUpRecommendationEngine.recommend(
                application=self.app_interview_a,
                existing_reminders=[],
                reference_date=date(2026, 11, 10),
                extra_context={"interview_date": "2026-11-10", "interview_date_source": invalid_src},
            )
            self.assertFalse(rec.has_recommendation, f"Should reject invalid source '{invalid_src}'")
            self.assertEqual(rec.application_context.get("interview_date_source"), "unavailable")

            tpl = FollowUpTemplateGenerator.generate(
                follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
                application=self.app_interview_a,
                candidate_profile={"full_name": "Alice Authenticated"},
                extra_context={"interview_date": "2026-11-10", "interview_date_source": invalid_src},
            )
            self.assertNotIn(" on 2026-11-10", tpl.body)
            self.assertEqual(tpl.context_metadata.get("interview_date_source"), "unavailable")

    def test_interview_timestamp_without_source_tag_rejected(self):
        """interview_timestamp without interview_date_source is rejected."""
        rec = FollowUpRecommendationEngine.recommend(
            application=self.app_interview_a,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"interview_timestamp": "2026-11-10T14:00:00Z"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertEqual(rec.application_context.get("interview_date_source"), "unavailable")

    def test_interview_timestamp_with_explicit_candidate_provided_source_accepted(self):
        """interview_timestamp with interview_date_source == 'candidate_provided' is accepted."""
        rec = FollowUpRecommendationEngine.recommend(
            application=self.app_interview_a,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"interview_timestamp": "2026-11-10T14:00:00Z", "interview_date_source": "candidate_provided"},
        )
        self.assertTrue(rec.has_recommendation)
        self.assertEqual(rec.recommended_date, "2026-11-11")
        self.assertEqual(rec.application_context.get("interview_date_source"), "candidate_provided")

    def test_template_and_recommendation_remain_consistent(self):
        """Engine and template behave identically on tagged vs untagged contexts."""
        # Untagged
        untagged_ctx = {"interview_date": "2026-11-10"}
        rec_untagged = FollowUpRecommendationEngine.recommend(
            application=self.app_interview_a,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context=untagged_ctx,
        )
        tpl_untagged = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=self.app_interview_a,
            candidate_profile={"full_name": "Alice Authenticated"},
            extra_context=untagged_ctx,
        )
        self.assertFalse(rec_untagged.has_recommendation)
        self.assertEqual(tpl_untagged.context_metadata.get("interview_date_source"), "unavailable")

        # Tagged
        tagged_ctx = {"interview_date": "2026-11-10", "interview_date_source": "candidate_provided"}
        rec_tagged = FollowUpRecommendationEngine.recommend(
            application=self.app_interview_a,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context=tagged_ctx,
        )
        tpl_tagged = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=self.app_interview_a,
            candidate_profile={"full_name": "Alice Authenticated"},
            extra_context=tagged_ctx,
        )
        self.assertTrue(rec_tagged.has_recommendation)
        self.assertEqual(tpl_tagged.context_metadata.get("interview_date_source"), "candidate_provided")

    def test_missing_or_rejected_dates_produce_neutral_wording_and_unavailable_metadata(self):
        """Missing or rejected dates produce neutral thank-you note without date phrasing."""
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=self.app_interview_a,
            candidate_profile={"full_name": "Alice Authenticated"},
            extra_context={},
        )
        self.assertIn("Thank you for taking the time to speak with me regarding the Research Scientist position", tpl.body)
        self.assertNotIn(" on ", tpl.body)
        self.assertEqual(tpl.context_metadata.get("interview_date_source"), "unavailable")
        self.assertIsNone(tpl.context_metadata.get("date_referenced"))

    # -------------------------------------------------------------------------
    # Finding C (Option B: No persisted source exists in database/models)
    # -------------------------------------------------------------------------

    def test_database_loaded_application_does_not_falsely_claim_application_record_provenance(self):
        """Database-loaded application has no persisted interview_date and never falsely claims application_record."""
        app = self.db.get_user_application(self.app_interview_a.id, self.user_a)
        self.assertIsNotNone(app)
        self.assertFalse(hasattr(app, "interview_date"))

        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
        )
        self.assertFalse(rec.has_recommendation)
        self.assertEqual(rec.application_context.get("interview_date_source"), "unavailable")

    def test_dynamically_attached_interview_date_on_application_is_not_claimed_as_application_record(self):
        """Even if interview_date is dynamically attached to an Application instance, it does not claim application_record."""
        app = Application(
            id=777,
            user_id=self.user_a,
            company_name="Google",
            job_title="SWE",
            status=ApplicationStatus.INTERVIEW.value,
        )
        setattr(app, "interview_date", "2026-11-10")

        # Without interview_date_source: "candidate_provided" in context, it is rejected
        rec = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
        )
        self.assertFalse(rec.has_recommendation)
        self.assertEqual(rec.application_context.get("interview_date_source"), "unavailable")

        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=app,
            candidate_profile={"full_name": "Alice Authenticated"},
        )
        self.assertNotIn("on 2026-11-10", tpl.body)
        self.assertEqual(tpl.context_metadata.get("interview_date_source"), "unavailable")

    def test_untagged_candidate_dates_rejected_under_option_b(self):
        """Under Option B, candidate dates without candidate_provided tag produce no recommendation."""
        rec = FollowUpRecommendationEngine.recommend(
            application=self.app_interview_a,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"interview_date": "2026-11-10"},
        )
        self.assertFalse(rec.has_recommendation)
        self.assertIsNone(rec.recommended_date)

    def test_explicit_candidate_provided_dates_labeled_correctly_under_option_b(self):
        """Under Option B, explicitly tagged candidate dates produce candidate_provided recommendation."""
        rec = FollowUpRecommendationEngine.recommend(
            application=self.app_interview_a,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={"interview_date": "2026-11-10", "interview_date_source": "candidate_provided"},
        )
        self.assertTrue(rec.has_recommendation)
        self.assertEqual(rec.application_context.get("interview_date_source"), "candidate_provided")
        self.assertIn("candidate-provided", rec.rationale)

    def test_missing_dates_produce_neutral_templates_and_no_recommendation_under_option_b(self):
        """Under Option B, missing dates produce neutral templates and no recommendation."""
        rec = FollowUpRecommendationEngine.recommend(
            application=self.app_interview_a,
            existing_reminders=[],
            reference_date=date(2026, 11, 10),
            extra_context={},
        )
        self.assertFalse(rec.has_recommendation)
        tpl = FollowUpTemplateGenerator.generate(
            follow_up_type=FollowUpType.THANK_YOU_NOTE.value,
            application=self.app_interview_a,
            candidate_profile={"full_name": "Alice Authenticated"},
            extra_context={},
        )
        self.assertNotIn(" on ", tpl.body)
        self.assertEqual(tpl.context_metadata.get("interview_date_source"), "unavailable")


if __name__ == "__main__":
    unittest.main()

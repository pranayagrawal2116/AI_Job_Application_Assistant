"""Integration tests for ApplicationFormFillingBroker (Phase C.1).

Verifies:
- ATS provider auto-detection (Keka, Greenhouse, Lever, Workday, Universal).
- SSRF and external domain safety verification.
- Safe authorized resume binary retrieval via FormPrefiller gateway.
- Audit event logging (EXTERNAL_FORM_AUTOFILLED) preserving application lifecycle invariant.
- Strict cross-user authorization enforcement.
"""

import pytest
from src.database.db_manager import DatabaseManager
from src.database.exceptions import SecurityAuthorizationError, CrossUserAccessError
from src.preparer.form_filling_broker import ApplicationFormFillingBroker, FormFillExecutionReport


class TestApplicationFormFillingBroker:
    """Test suite for ApplicationFormFillingBroker."""

    def test_identify_ats_provider(self):
        """Verify pattern detection for various ATS providers."""
        broker = ApplicationFormFillingBroker()

        assert broker.identify_ats_provider("https://blueflamelabs.keka.com/careers/applyjob/76776") == "KEKA"
        assert broker.identify_ats_provider("https://company.keka.com/careers/jobdetails/123") == "KEKA"
        assert broker.identify_ats_provider("https://boards.greenhouse.io/stripe/jobs/456") == "GREENHOUSE"
        assert broker.identify_ats_provider("https://jobs.lever.co/reddit/789") == "LEVER"
        assert broker.identify_ats_provider("https://workday.wd5.myworkdayjobs.com/en-US/careers") == "WORKDAY"
        assert broker.identify_ats_provider("https://careers.acme.corp/job/101") == "UNIVERSAL"

    def test_domain_safety_validation(self):
        """Verify public URLs pass and private/loopback/cloud-metadata URLs raise SecurityAuthorizationError."""
        broker = ApplicationFormFillingBroker()

        # Public URLs pass and return validated domain hostname
        domain = broker.validate_external_domain("https://blueflamelabs.keka.com/careers/applyjob/76776")
        assert domain == "blueflamelabs.keka.com"

        domain_gh = broker.validate_external_domain("https://boards.greenhouse.io/stripe/jobs/123")
        assert domain_gh == "boards.greenhouse.io"

        # Loopback rejected
        with pytest.raises(SecurityAuthorizationError):
            broker.validate_external_domain("http://127.0.0.1:8000/admin")

        with pytest.raises(SecurityAuthorizationError):
            broker.validate_external_domain("http://localhost:3000/apply")

        # Cloud metadata rejected
        with pytest.raises(SecurityAuthorizationError):
            broker.validate_external_domain("http://169.254.169.254/latest/meta-data")

    def test_record_autofill_audit_event_leaves_status_intact(self):
        """Verify audit event recording records EXTERNAL_FORM_AUTOFILLED without changing application status to SUBMITTED."""
        db = DatabaseManager()
        broker = ApplicationFormFillingBroker(db=db)

        # Create dummy user and application
        with db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('test_audit@example.com', 'hash', 'salt', 'Test')"
            )
            user_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO applications (user_id, status, job_title, company_name) VALUES (?, 'APPROVED', 'Dev', 'Test Corp')",
                (user_id,)
            )
            app_id = cursor.lastrowid

        try:
            report = FormFillExecutionReport(
                execution_id="exec-12345",
                application_id=app_id,
                user_id=user_id,
                ats_provider="KEKA",
                target_url="https://test.keka.com/apply",
                validated_domain="test.keka.com",
                resume_uploaded=True,
                resume_id=1,
                resume_version_num=1,
                resume_file_hash="abc",
                resume_filename="resume.pdf",
                ats_parsing_completed=True,
                total_fields_detected=5,
                fields_populated_count=3,
                fields_ats_parsed_count=2,
                fields_preserved_count=0,
                fields_manual_review_count=0,
                fields_unmatched_count=0,
                anti_automation_detected=False,
                submission_prevented=True,
                status="SUCCESS",
            )

            event = broker._record_autofill_audit_event(report)
            assert event is not None
            assert event.id is not None
            assert event.id > 0

            # Verify application status was NOT changed to SUBMITTED (Strict Human-in-the-Loop invariant)
            app = db.get_application_by_id(app_id)
            assert app.status == "APPROVED"
            assert app.status != "SUBMITTED"

            # Verify event was recorded in application_events
            with db.transaction() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT event_type, user_id, application_id FROM application_events WHERE id = ?",
                    (event.id,)
                )
                ev = cursor.fetchone()
                assert ev[0] == "EXTERNAL_FORM_AUTOFILLED"
                assert ev[1] == user_id
                assert ev[2] == app_id
        finally:
            db.delete_user_account_data(user_id)

    def test_cross_user_resume_binary_access_rejected(self):
        """Verify candidate A cannot access resume binary of candidate B."""
        db = DatabaseManager()
        broker = ApplicationFormFillingBroker(db=db)

        with db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('user_a@example.com', 'hash', 'salt', 'User A')"
            )
            user_a = cursor.lastrowid

            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('user_b@example.com', 'hash', 'salt', 'User B')"
            )
            user_b = cursor.lastrowid

            cursor.execute(
                "INSERT INTO applications (user_id, status, job_title, company_name) VALUES (?, 'APPROVED', 'Dev', 'Corp B')",
                (user_b,)
            )
            app_b = cursor.lastrowid

        try:
            # User A attempts to access User B's application binary
            with pytest.raises((CrossUserAccessError, SecurityAuthorizationError)):
                broker.get_verified_resume_bytes(application_id=app_b, user_id=user_a, ticket="dummy-ticket")
        finally:
            db.delete_user_account_data(user_a)
            db.delete_user_account_data(user_b)

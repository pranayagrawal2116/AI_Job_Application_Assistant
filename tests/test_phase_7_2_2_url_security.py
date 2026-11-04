"""Phase 7.2.2 URL Validation, DNS Resolution, and Fragment Redaction Tests.

Verifies:
1. DashboardService supports an injectable url_resolver for deterministic DNS testing.
2. create_candidate_application performs full DNS validation (no skip_dns=True bypass).
3. Private, loopback, cloud metadata, carrier-grade NAT, and mixed DNS resolutions are rejected.
4. log_external_application_url_opened validates URLs, preserves status, and redacts sensitive data.
5. _redact_sensitive_url completely strips URL fragments (preventing OAuth token leaks in audit events).
6. _redact_sensitive_url redacts sensitive query parameters (case-insensitive, unquoted) while preserving non-sensitive parameters.
"""

import os
import tempfile
from typing import List
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import UnsafeURLError
from src.security.session_manager import SessionManager


class TestPhase722URLSecurity(unittest.TestCase):
    """Tests DNS resolution validation, SSRF boundary protection, and URL audit redaction."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_url_sec.db")
        self.db = DatabaseManager(self.db_path)
        self.session_mgr = SessionManager.get_instance()

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'candidate.url@example.com', 'h1', 's1', 'URL Candidate')"
            )
        self.user_id = 1
        self.session = self.session_mgr.authenticate_candidate(
            candidate_id="url_cand",
            candidate_name="URL Candidate",
            user_id=self.user_id,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    # =========================================================================
    # 1. INJECTABLE DNS RESOLVER TESTS
    # =========================================================================

    def test_injected_resolver_allows_public_ip(self):
        """DashboardService allows URL when injected resolver returns valid public routable IP."""
        def mock_public_resolver(host: str, port: int) -> List[str]:
            return ["142.250.190.46"]

        service = DashboardService(db_manager=self.db, url_resolver=mock_public_resolver)
        app = service.create_candidate_application(
            session_id=self.session.session_id,
            company_name="Google",
            job_title="Software Engineer",
            job_url="https://careers.google.com/jobs/results/42",
        )
        self.assertIsNotNone(app.id)
        self.assertEqual(app.external_application_url, "https://careers.google.com/jobs/results/42")

    def test_injected_resolver_rejects_private_ips(self):
        """DashboardService rejects URLs when injected resolver returns private, loopback, or cloud metadata IPs."""
        test_cases = [
            ("127.0.0.1", "Loopback"),
            ("10.0.0.5", "RFC1918 10/8"),
            ("192.168.1.100", "RFC1918 192.168/16"),
            ("172.16.50.1", "RFC1918 172.16/12"),
            ("169.254.169.254", "Cloud Metadata Link-Local"),
            ("100.64.0.1", "Carrier-Grade NAT"),
            ("0.0.0.0", "Current Network"),
            ("::1", "IPv6 Loopback"),
            ("fe80::1", "IPv6 Link-Local"),
            ("fc00::1", "IPv6 Unique Local"),
        ]

        for restricted_ip, label in test_cases:
            def mock_restricted_resolver(host: str, port: int) -> List[str]:
                return [restricted_ip]

            service = DashboardService(db_manager=self.db, url_resolver=mock_restricted_resolver)
            with self.assertRaises(UnsafeURLError, msg=f"Should reject {label} ({restricted_ip})"):
                service.create_candidate_application(
                    session_id=self.session.session_id,
                    company_name="Bad IP Corp",
                    job_title="Engineer",
                    job_url="https://corporate-jobs.internal/apply",
                )

    def test_injected_resolver_rejects_mixed_ips(self):
        """If any resolved IP address is private/restricted, the domain is rejected."""
        def mock_mixed_resolver(host: str, port: int) -> List[str]:
            # Returns both public IP and private internal IP (DNS rebinding / dual-homed)
            return ["142.250.190.46", "10.0.0.1"]

        service = DashboardService(db_manager=self.db, url_resolver=mock_mixed_resolver)
        with self.assertRaises(UnsafeURLError):
            service.create_candidate_application(
                session_id=self.session.session_id,
                company_name="Mixed IP Corp",
                job_title="Engineer",
                job_url="https://dual-homed-target.com/jobs/1",
            )

    def test_injected_resolver_rejects_empty_or_failing_dns(self):
        """Empty resolution records or resolver errors raise UnsafeURLError."""
        def mock_empty_resolver(host: str, port: int) -> List[str]:
            return []

        service = DashboardService(db_manager=self.db, url_resolver=mock_empty_resolver)
        with self.assertRaises(UnsafeURLError):
            service.create_candidate_application(
                session_id=self.session.session_id,
                company_name="Empty DNS Corp",
                job_title="Engineer",
                job_url="https://non-existent-domain.xyz/apply",
            )

    # =========================================================================
    # 2. LOG_EXTERNAL_APPLICATION_URL_OPENED CHECKS
    # =========================================================================

    def test_log_external_application_url_opened_preserves_status_and_validates(self):
        """log_external_application_url_opened validates URL, does not mutate status, and logs event."""
        def mock_public_resolver(host: str, port: int) -> List[str]:
            return ["142.250.190.46"]

        service = DashboardService(db_manager=self.db, url_resolver=mock_public_resolver)
        app = service.create_candidate_application(
            session_id=self.session.session_id,
            company_name="Employer Inc",
            job_title="Staff Engineer",
            status="PREPARING",
            job_url="https://careers.google.com/jobs/101?source=board#fragment_should_be_stripped",
        )

        # Open link
        service.log_external_application_url_opened(
            application_id=app.id,
            session_id=self.session.session_id,
        )

        # Verify application status strictly unchanged
        fresh_app = self.db.get_user_application(app.id, self.user_id)
        self.assertEqual(fresh_app.status, "PREPARING")

        # Verify timeline event was added
        events = self.db.get_application_events(app.id, self.user_id)
        opened_events = [e for e in events if e.event_type == "EXTERNAL_APPLICATION_URL_OPENED"]
        self.assertEqual(len(opened_events), 1)
        import json
        payload = json.loads(opened_events[0].event_payload_json)
        self.assertEqual(payload["application_status_preserved"], "PREPARING")
        # Fragment was stripped from opened_url
        self.assertNotIn("fragment_should_be_stripped", payload["opened_url"])
        self.assertNotIn("#", payload["opened_url"])

    # =========================================================================
    # 3. URL FRAGMENT STRIPPING AND QUERY REDACTION
    # =========================================================================

    def test_redact_sensitive_url_strips_fragments_completely(self):
        """URL fragments are completely stripped to prevent OAuth token leaks in audit events."""
        test_urls = [
            (
                "https://jobs.example.com/apply#access_token=ya29.secret_oauth_token",
                "https://jobs.example.com/apply",
            ),
            (
                "https://careers.example.com/positions/42?job_id=42#id_token=ey.jwt.secret",
                "https://careers.example.com/positions/42?job_id=42",
            ),
            (
                "https://work.example.com/form#section-3",
                "https://work.example.com/form",
            ),
        ]

        for input_url, expected_url in test_urls:
            redacted = DashboardService._redact_sensitive_url(input_url)
            self.assertEqual(redacted, expected_url)
            self.assertNotIn("#", redacted)

    def test_redact_sensitive_url_redacts_tokens_and_preserves_non_sensitive(self):
        """Sensitive parameters (tokens, secrets, passwords) are redacted; non-sensitive preserved."""
        url = (
            "https://ats.example.com/submit?"
            "job_id=12345"
            "&token=secret_value_1"
            "&TOKEN=secret_value_2"
            "&auth_code=sensitive_code"
            "&api_key=sk_live_abc123"
            "&password=mysecretpassword"
            "&session_id=sess_active_789"
            "&jwt=header.payload.sig"
            "&source=linkedin"
            "&utm_campaign=hiring_2026"
            "&category=engineering"
            "&page=2"
            "#private_hash_data"
        )

        redacted = DashboardService._redact_sensitive_url(url)

        # Sensitive parameters redacted
        self.assertIn("token=REDACTED", redacted)
        self.assertIn("TOKEN=REDACTED", redacted)
        self.assertIn("auth_code=REDACTED", redacted)
        self.assertIn("api_key=REDACTED", redacted)
        self.assertIn("password=REDACTED", redacted)
        self.assertIn("session_id=REDACTED", redacted)
        self.assertIn("jwt=REDACTED", redacted)

        # Actual secrets not present
        self.assertNotIn("secret_value_1", redacted)
        self.assertNotIn("secret_value_2", redacted)
        self.assertNotIn("sensitive_code", redacted)
        self.assertNotIn("sk_live_abc123", redacted)
        self.assertNotIn("mysecretpassword", redacted)
        self.assertNotIn("sess_active_789", redacted)

        # Non-sensitive parameters preserved intact
        self.assertIn("job_id=12345", redacted)
        self.assertIn("source=linkedin", redacted)
        self.assertIn("utm_campaign=hiring_2026", redacted)
        self.assertIn("category=engineering", redacted)
        self.assertIn("page=2", redacted)

        # Fragment completely stripped
        self.assertNotIn("private_hash_data", redacted)
        self.assertNotIn("#", redacted)

    def test_redact_sensitive_url_unquotes_keys(self):
        """URL-encoded sensitive parameter keys like token%5Fid are properly identified and redacted."""
        url = "https://ats.example.com/portal?token%5Fid=secret_token_val&user_id=101"
        redacted = DashboardService._redact_sensitive_url(url)
        self.assertIn("REDACTED", redacted)
        self.assertNotIn("secret_token_val", redacted)
        self.assertIn("user_id=101", redacted)

    def test_redact_sensitive_url_strips_netloc_credentials(self):
        """Embedded username and password in netloc are stripped from the URL."""
        url = "https://admin:supersecret@careers.example.com/dashboard?job_id=99"
        redacted = DashboardService._redact_sensitive_url(url)
        self.assertNotIn("admin", redacted)
        self.assertNotIn("supersecret", redacted)
        self.assertNotIn("@", redacted)
        self.assertEqual(redacted, "https://careers.example.com/dashboard?job_id=99")


if __name__ == "__main__":
    unittest.main()

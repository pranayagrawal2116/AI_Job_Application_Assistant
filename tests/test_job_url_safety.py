"""Security and Robustness Tests for Job URL Fetcher and SSRF Defense Engine.

Verifies SSRF boundary enforcement, DNS rebinding defenses, open redirect validation,
anti-bot / restriction detection, and response size limits.
"""

from unittest.mock import MagicMock, patch
import unittest

from src.database.exceptions import (
    FileTooLargeError,
    UnsafeURLError,
    URLFetchRestrictedError,
)
from src.scraper.url_fetcher import URLJobFetcher
from src.security.url_validator import URLSafetyValidator


class TestJobURLSafety(unittest.TestCase):
    """Test suite for URL validation, SSRF defense, and anti-bot handling."""

    def setUp(self):
        self.validator = URLSafetyValidator()
        self.fetcher = URLJobFetcher()
        # Mock DNS resolution by default to avoid slow external network lookups in unit tests
        self.dns_patcher = patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))])
        self.mock_dns = self.dns_patcher.start()

    def tearDown(self):
        self.dns_patcher.stop()

    def test_ssrf_blocked_schemes(self):
        """Disallowed schemes like file, ftp, gopher, and javascript are rejected."""
        dangerous_urls = [
            "file:///etc/passwd",
            "file:///C:/Windows/win.ini",
            "ftp://ftp.example.com/file.txt",
            "gopher://example.com:70/1",
            "javascript:alert(1)",
            "data:text/html,<h1>Hello</h1>",
        ]
        for url in dangerous_urls:
            with self.assertRaises(UnsafeURLError):
                self.validator.validate_url(url)

    def test_ssrf_blocked_private_ip_literals(self):
        """Loopback, RFC 1918, carrier-grade NAT, and cloud metadata IP literals are blocked."""
        private_urls = [
            "http://127.0.0.1/admin",
            "http://127.0.0.2:8080/metrics",
            "http://10.0.0.5/internal/jobs",
            "http://172.16.0.1/jobs",
            "http://192.168.1.100/status",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/cgnat",
            "http://[::1]/ipv6_loopback",
            "http://[fc00::1]/unique_local",
        ]
        for url in private_urls:
            with self.assertRaises(UnsafeURLError):
                self.validator.validate_url(url)

    def test_ssrf_blocked_hostnames_and_suffixes(self):
        """Internal hostnames and private domain suffixes are rejected."""
        internal_urls = [
            "http://localhost:8080/jobs",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://instance-data/latest/meta-data/",
            "http://app.internal/careers",
            "http://server.local/postings",
            "http://intranet.corp/jobs",
            "http://home.lan/jobs",
        ]
        for url in internal_urls:
            with self.assertRaises(UnsafeURLError):
                self.validator.validate_url(url)

    def test_ssrf_blocked_non_standard_ports(self):
        """Restricted non-standard ports (SSH, MySQL, Redis) are rejected."""
        bad_port_urls = [
            "http://example.com:22/job",
            "http://example.com:3306/db",
            "http://example.com:6379/redis",
            "http://example.com:25/smtp",
        ]
        for url in bad_port_urls:
            with self.assertRaises(UnsafeURLError):
                self.validator.validate_url(url)

    def test_ssrf_dns_resolution_rebinding_defense(self):
        """Domains resolving to private IP addresses are blocked during DNS inspection."""
        self.mock_dns.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 80)),
        ]
        with self.assertRaises(UnsafeURLError) as ctx:
            self.validator.validate_url("http://evil.example.com/job")
        self.assertIn("resolves to private/restricted IP", str(ctx.exception))

    def test_open_redirect_to_private_ip_blocked(self):
        """Redirect from safe initial URL to internal private IP is intercepted and blocked."""
        with patch("requests.Session.get") as mock_get:
            redirect_response = MagicMock()
            redirect_response.status_code = 302
            redirect_response.headers = {"Location": "http://127.0.0.1/admin"}

            mock_get.return_value = redirect_response

            with self.assertRaises(UnsafeURLError) as ctx:
                self.fetcher.fetch_job_url("https://public-jobs.example.com/listing/123")
            self.assertIn("Access to private, loopback, or non-routable IP", str(ctx.exception))

    def test_anti_bot_http_status_codes_raise_restriction(self):
        """HTTP 401, 403, and 429 status codes raise URLFetchRestrictedError."""
        status_codes = [401, 403, 429]

        for code in status_codes:
            with patch("requests.Session.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = code
                mock_resp.headers = {"Content-Type": "text/html"}
                mock_get.return_value = mock_resp

                with self.assertRaises(URLFetchRestrictedError) as ctx:
                    self.fetcher.fetch_job_url("https://careers.example.com/posting/456")
                self.assertIn("Automated access was restricted", str(ctx.exception))
                self.assertEqual(ctx.exception.restriction_type, f"HTTP_{code}")

    def test_anti_bot_page_signatures_detected(self):
        """Cloudflare, PerimeterX, and LinkedIn authwall HTML pages raise restriction error."""
        signatures = [
            ("<html><title>Just a moment...</title><body>cf-turnstile-challenge</body></html>", "Cloudflare Challenge"),
            ("<html><body>Access Denied: PerimeterX Bot Defense active</body></html>", "PerimeterX Bot Defense"),
            ("<html><head><title>LinkedIn</title></head><body>Sign in to view full job posting</body></html>", "Login Wall"),
        ]

        for html_content, expected_label in signatures:
            with patch("requests.Session.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.headers = {"Content-Type": "text/html"}
                mock_resp.encoding = "utf-8"
                mock_resp.iter_content = MagicMock(return_value=[html_content.encode("utf-8")])
                mock_get.return_value = mock_resp

                with self.assertRaises(URLFetchRestrictedError) as ctx:
                    self.fetcher.fetch_job_url("https://careers.example.com/job/789")
                self.assertEqual(ctx.exception.restriction_type, expected_label)

    def test_response_size_limit_enforced(self):
        """Responses exceeding 5 MB download limit are terminated with FileTooLargeError."""
        oversized_chunks = [b"A" * 1024 * 1024 for _ in range(6)]  # 6 MB

        with patch("requests.Session.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Content-Type": "text/html"}
            mock_resp.iter_content = MagicMock(return_value=oversized_chunks)
            mock_get.return_value = mock_resp

            with self.assertRaises(FileTooLargeError):
                self.fetcher.fetch_job_url("https://careers.example.com/massive-page")

    def test_ssrf_ipv4_mapped_ipv6_blocked(self):
        """IPv4-mapped IPv6 representations of loopback, private, and metadata IPs are strictly blocked."""
        mapped_urls = [
            "http://[::ffff:127.0.0.1]/admin",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[::ffff:10.0.0.1]/intranet",
            "http://[::ffff:192.168.1.1]/gateway",
        ]
        for url in mapped_urls:
            with self.assertRaises(UnsafeURLError):
                self.validator.validate_url(url)

    def test_connection_pinning_adapter_attaches_validated_ip(self):
        """PinnedHTTPAdapter correctly propagates the pinned public IP to its connection pools."""
        from src.scraper.url_fetcher import PinnedHTTPAdapter
        adapter = PinnedHTTPAdapter(pinned_ip="93.184.216.34")
        adapter.init_poolmanager(connections=2, maxsize=2)
        pool = adapter.poolmanager.connection_from_host("example.com", scheme="https", port=443)
        self.assertEqual(pool.pinned_ip, "93.184.216.34")
        conn = pool._new_conn()
        self.assertEqual(conn.pinned_ip, "93.184.216.34")
        # Ensure host is preserved for TLS SNI and cert check
        self.assertEqual(conn.host, "example.com")

    def test_session_trust_env_disabled(self):
        """Requests session enforces trust_env=False to prevent ambient proxy SSRF bypasses."""
        with patch("requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value.__enter__.return_value = mock_session
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Content-Type": "text/html"}
            mock_resp.encoding = "utf-8"
            mock_resp.iter_content = MagicMock(return_value=[b"<html><title>Job</title><body>Clean Job</body></html>"])
            mock_session.get.return_value = mock_resp

            self.fetcher.fetch_job_url("https://jobs.example.com/posting/1")
            self.assertFalse(mock_session.trust_env)

    def test_response_lifecycle_closed_on_success_and_error(self):
        """Responses are deterministically closed on success, redirects, and error paths."""
        # 1. Success path closes response
        with patch("requests.Session.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Content-Type": "text/html"}
            mock_resp.encoding = "utf-8"
            mock_resp.iter_content = MagicMock(return_value=[b"<html><body>Engineer at Acme</body></html>"])
            mock_get.return_value = mock_resp

            self.fetcher.fetch_job_url("https://jobs.example.com/posting/1")
            mock_resp.close.assert_called()

        # 2. Redirect path closes original response
        with patch("requests.Session.get") as mock_get:
            redirect_resp = MagicMock()
            redirect_resp.status_code = 301
            redirect_resp.headers = {"Location": "https://jobs.example.com/posting/2"}

            final_resp = MagicMock()
            final_resp.status_code = 200
            final_resp.headers = {"Content-Type": "text/html"}
            final_resp.encoding = "utf-8"
            final_resp.iter_content = MagicMock(return_value=[b"<html><body>Content</body></html>"])

            mock_get.side_effect = [redirect_resp, final_resp]

            self.fetcher.fetch_job_url("https://jobs.example.com/posting/1")
            redirect_resp.close.assert_called()
            final_resp.close.assert_called()

        # 3. Error path (e.g. 403 Forbidden) closes response
        with patch("requests.Session.get") as mock_get:
            err_resp = MagicMock()
            err_resp.status_code = 403
            err_resp.headers = {"Content-Type": "text/html"}
            mock_get.return_value = err_resp

            with self.assertRaises(URLFetchRestrictedError):
                self.fetcher.fetch_job_url("https://jobs.example.com/posting/protected")
            err_resp.close.assert_called()


if __name__ == "__main__":
    unittest.main()

"""Real HTTPS Integration Tests for Connection Pinning and DNS Rebinding Resistance.

Verifies end-to-end transport security using real local HTTPS sockets, valid RFC 5280
X.509 certificates with SANs, TLS SNI validation, HTTP Host header verification,
strict certificate validation, and deterministic DNS rebinding defense.
"""

import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import socket
import ssl
import tempfile
import threading
import time
from typing import Any, List, Optional, Tuple, cast
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import requests

from src.database.exceptions import (
    FileTooLargeError,
    UnsafeURLError,
    URLFetchRestrictedError,
)
from src.scraper.url_fetcher import PinnedHTTPAdapter, URLJobFetcher
from src.security.url_validator import URLSafetyValidator


class FastHTTPServer(HTTPServer):
    """Custom HTTPServer that overrides server_bind to avoid reverse DNS delays in sandboxes."""

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()
        self.server_name = str(self.server_address[0])
        self.server_port = self.server_address[1]


def generate_test_pki(san_dns_names: List[str]) -> Tuple[bytes, bytes, bytes]:
    """Generates a valid test Root CA and a server certificate with SANs matching RFC 5280.
    
    Returns:
        (ca_pem_bytes, srv_cert_pem_bytes, srv_key_pem_bytes)
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Root CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Integration Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # 2. Server Certificate
    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san_dns_names[0])])
    srv_builder = (
        x509.CertificateBuilder()
        .subject_name(srv_name)
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in san_dns_names]), critical=False)
    )
    srv_cert = srv_builder.sign(ca_key, hashes.SHA256())

    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    srv_cert_pem = srv_cert.public_bytes(serialization.Encoding.PEM)
    srv_key_pem = srv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    return ca_pem, srv_cert_pem, srv_key_pem


class TestPinnedHTTPSIntegration(unittest.TestCase):
    """End-to-end integration tests using real local HTTPS servers and live TLS handshakes."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ca_pem, self.srv_cert_pem, self.srv_key_pem = generate_test_pki(["careers.test.example"])

        self.ca_file = os.path.join(self.temp_dir.name, "ca.crt")
        self.srv_cert_file = os.path.join(self.temp_dir.name, "srv.crt")
        self.srv_key_file = os.path.join(self.temp_dir.name, "srv.key")

        with open(self.ca_file, "wb") as f:
            f.write(self.ca_pem)
        with open(self.srv_cert_file, "wb") as f:
            f.write(self.srv_cert_pem)
        with open(self.srv_key_file, "wb") as f:
            f.write(self.srv_key_pem)

        self.server: Optional[FastHTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None

    def tearDown(self) -> None:
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
        self.temp_dir.cleanup()

    def _start_https_server(self, handler_cls: type[BaseHTTPRequestHandler]) -> Tuple[int, List[str]]:
        """Starts a live TLS test server with SNI callback recording."""
        received_sni: List[str] = []

        def sni_callback(ssl_sock, server_name, initial_context):
            received_sni.append(server_name)

        server = FastHTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_port

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(self.srv_cert_file, self.srv_key_file)
        ssl_ctx.sni_callback = sni_callback
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)

        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        self.server = server
        self.server_thread = t
        return port, received_sni

    def test_real_https_connection_pins_ip_preserves_sni_and_host_header(self) -> None:
        """Real HTTPS socket verifies pinned IP connection, TLS SNI, and HTTP Host header."""
        received_hosts: List[str] = []

        class JobHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                received_hosts.append(self.headers.get("Host", ""))
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    b"<html><head><title>Senior Engineer Job</title></head>"
                    b"<body><h1>Senior Python Engineer at Acme</h1><p>Full-time role in tech.</p></body></html>"
                )

            def log_message(self, format, *args):
                pass

        port, received_sni = self._start_https_server(JobHandler)

        # Injected test resolver maps careers.test.example -> 127.0.0.1
        def test_resolver(host: str, p: int) -> List[str]:
            if host == "careers.test.example":
                return ["127.0.0.1"]
            return []

        with URLSafetyValidator.allow_test_ip("127.0.0.1"):
            fetcher = URLJobFetcher(
                resolver=test_resolver,
                ca_bundle=self.ca_file,
            )
            # URL uses target domain name with NO real DNS record
            result = fetcher.fetch_job_url(f"https://careers.test.example:{port}/positions/42")

        # 1. Assert content extraction was successful over real HTTPS
        self.assertEqual(result.status_code, 200)
        self.assertIn("Senior Python Engineer", result.raw_text)

        # 2. Assert TLS SNI transmitted over socket matches target hostname
        self.assertEqual(received_sni, ["careers.test.example"])

        # 3. Assert HTTP Host header transmitted over socket matches target hostname & port
        self.assertEqual(received_hosts, [f"careers.test.example:{port}"])

    def test_strict_tls_certificate_hostname_validation_fails_on_mismatch(self) -> None:
        """Certificate hostname mismatch strictly terminates connection without weakening validation."""
        class DummyHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()

            def log_message(self, format, *args):
                pass

        port, _ = self._start_https_server(DummyHandler)

        # Resolver returns 127.0.0.1 for untrusted hostname
        def test_resolver(host: str, p: int) -> List[str]:
            return ["127.0.0.1"]

        with URLSafetyValidator.allow_test_ip("127.0.0.1"):
            fetcher = URLJobFetcher(
                resolver=test_resolver,
                ca_bundle=self.ca_file,
            )
            # Server cert SAN is 'careers.test.example'. URL requests 'untrusted-host.test.example'.
            with self.assertRaises(URLFetchRestrictedError) as ctx:
                fetcher.fetch_job_url(f"https://untrusted-host.test.example:{port}/jobs")
            
            self.assertIn("Unable to reach job URL", str(ctx.exception))
            # Verify the underlying cause is SSLError / SSLCertVerificationError (Hostname mismatch)
            underlying = str(ctx.exception)
            self.assertTrue("SSL" in underlying or "CERTIFICATE_VERIFY_FAILED" in underlying)

    def test_strict_tls_certificate_validation_fails_with_untrusted_ca(self) -> None:
        """Untrusted or missing CA bundle causes TLS handshake verification failure."""
        class DummyHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()

            def log_message(self, format, *args):
                pass

        port, _ = self._start_https_server(DummyHandler)

        # Generate a separate untrusted CA file
        untrusted_ca_pem, _, _ = generate_test_pki(["other.example"])
        untrusted_ca_file = os.path.join(self.temp_dir.name, "untrusted_ca.crt")
        with open(untrusted_ca_file, "wb") as f:
            f.write(untrusted_ca_pem)

        def test_resolver(host: str, p: int) -> List[str]:
            return ["127.0.0.1"]

        with URLSafetyValidator.allow_test_ip("127.0.0.1"):
            fetcher = URLJobFetcher(
                resolver=test_resolver,
                ca_bundle=untrusted_ca_file,
            )
            with self.assertRaises(URLFetchRestrictedError) as ctx:
                fetcher.fetch_job_url(f"https://careers.test.example:{port}/jobs")
            self.assertIn("Unable to reach job URL", str(ctx.exception))

    def test_dns_rebinding_connection_remains_pinned_to_initial_ip(self) -> None:
        """DNS rebinding attack: changing DNS answer after initial validation does NOT alter socket destination."""
        server_hits: List[str] = []

        class Server1Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                server_hits.append("server1")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>Server 1 Response</body></html>")

            def log_message(self, format, *args):
                pass

        port, _ = self._start_https_server(Server1Handler)

        # DNS resolver counter: first call returns 127.0.0.1 (Server 1), subsequent call returns different IP
        dns_call_count = [0]

        def dynamic_dns_resolver(host: str, p: int) -> List[str]:
            dns_call_count[0] += 1
            if dns_call_count[0] == 1:
                return ["127.0.0.1"]
            # Attacker's second DNS resolution switches to an unauthorized target
            return ["10.0.0.1"]

        with URLSafetyValidator.allow_test_ip("127.0.0.1"):
            fetcher = URLJobFetcher(
                resolver=dynamic_dns_resolver,
                ca_bundle=self.ca_file,
            )
            # Fetch URL: adapter pins 127.0.0.1
            res = fetcher.fetch_job_url(f"https://careers.test.example:{port}/jobs/rebind")

        self.assertEqual(res.status_code, 200)
        self.assertIn("Server 1 Response", res.raw_text)
        # Sockets connected to Server 1, immune to DNS mutation
        self.assertEqual(server_hits, ["server1"])

    def test_dns_rebinding_redirect_to_private_ip_aborted_before_connection(self) -> None:
        """Redirecting to a domain resolving to a private/loopback IP is intercepted and aborted."""
        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                # Redirects to a rebound domain
                self.send_header("Location", "https://rebound.test.example/internal-endpoint")
                self.end_headers()

            def log_message(self, format, *args):
                pass

        port, _ = self._start_https_server(RedirectHandler)

        def rebinding_resolver(host: str, p: int) -> List[str]:
            if host == "careers.test.example":
                return ["127.0.0.1"]
            elif host == "rebound.test.example":
                # Attacker's redirect destination resolves to an unauthorized private network IP
                return ["10.200.0.1"]
            return []

        with URLSafetyValidator.allow_test_ip("127.0.0.1"):
            fetcher = URLJobFetcher(
                resolver=rebinding_resolver,
                ca_bundle=self.ca_file,
            )
            with self.assertRaises(UnsafeURLError) as ctx:
                fetcher.fetch_job_url(f"https://careers.test.example:{port}/initial")

            # Must fail safely with UnsafeURLError before any outbound request is attempted to 10.200.0.1
            self.assertIn("resolves to private/restricted IP '10.200.0.1'", str(ctx.exception))

    def test_real_https_redirect_creates_fresh_pin_and_closes_old_adapter(self) -> None:
        """When an HTTPS redirect occurs, a fresh destination validation and pinned adapter are created."""
        events: List[str] = []

        class RedirectHopHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/hop1":
                    events.append("hop1")
                    self.send_response(302)
                    self.send_header("Location", f"https://careers.test.example:{self.server.server_port}/hop2")
                    self.end_headers()
                elif self.path == "/hop2":
                    events.append("hop2")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>Final Hop Content</h1></body></html>")

            def log_message(self, format, *args):
                pass

        port, received_sni = self._start_https_server(RedirectHopHandler)

        def test_resolver(host: str, p: int) -> List[str]:
            return ["127.0.0.1"]

        with URLSafetyValidator.allow_test_ip("127.0.0.1"):
            fetcher = URLJobFetcher(
                resolver=test_resolver,
                ca_bundle=self.ca_file,
            )
            result = fetcher.fetch_job_url(f"https://careers.test.example:{port}/hop1")

        self.assertEqual(result.status_code, 200)
        self.assertIn("Final Hop Content", result.raw_text)
        self.assertEqual(events, ["hop1", "hop2"])
        self.assertEqual(received_sni, ["careers.test.example", "careers.test.example"])

    def test_connection_pool_not_reused_for_different_pinned_destinations(self) -> None:
        """PinnedHTTPAdapter creates distinct connection pools pinned specifically to each IP."""
        adapter_1 = PinnedHTTPAdapter(pinned_ip="93.184.216.34")
        adapter_1.init_poolmanager(connections=2, maxsize=2)
        pool_1 = adapter_1.poolmanager.connection_from_host("example.com", scheme="https", port=443)

        adapter_2 = PinnedHTTPAdapter(pinned_ip="151.101.1.69")
        adapter_2.init_poolmanager(connections=2, maxsize=2)
        pool_2 = adapter_2.poolmanager.connection_from_host("example.com", scheme="https", port=443)

        self.assertNotEqual(getattr(pool_1, "pinned_ip", None), getattr(pool_2, "pinned_ip", None))
        self.assertEqual(getattr(pool_1, "pinned_ip", None), "93.184.216.34")
        self.assertEqual(getattr(pool_2, "pinned_ip", None), "151.101.1.69")
        adapter_1.close()
        adapter_2.close()

    def test_streamed_response_size_cap_enforced_real_sockets(self) -> None:
        """Exceeding 5 MB max response limit over a real TLS socket aborts with FileTooLargeError."""
        class StreamLargeHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                # Send 6 MB of data in 1 MB chunks
                chunk = b"A" * (1024 * 1024)
                for _ in range(6):
                    try:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        break

            def log_message(self, format, *args):
                pass

        port, _ = self._start_https_server(StreamLargeHandler)

        def test_resolver(host: str, p: int) -> List[str]:
            return ["127.0.0.1"]

        with URLSafetyValidator.allow_test_ip("127.0.0.1"):
            fetcher = URLJobFetcher(
                resolver=test_resolver,
                ca_bundle=self.ca_file,
                max_bytes=5 * 1024 * 1024,
            )
            with self.assertRaises(FileTooLargeError):
                fetcher.fetch_job_url(f"https://careers.test.example:{port}/massive")

    def test_read_timeout_enforced_real_sockets(self) -> None:
        """Enforces read timeout over real sockets and terminates safely without leaking."""
        class SlowHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                # Sleep longer than the client's read timeout
                time.sleep(2.0)
                try:
                    self.send_response(200)
                    self.end_headers()
                except Exception:
                    pass

            def log_message(self, format, *args):
                pass

        port, _ = self._start_https_server(SlowHandler)

        def test_resolver(host: str, p: int) -> List[str]:
            return ["127.0.0.1"]

        with URLSafetyValidator.allow_test_ip("127.0.0.1"):
            fetcher = URLJobFetcher(
                resolver=test_resolver,
                ca_bundle=self.ca_file,
                connect_timeout=2.0,
                read_timeout=0.4,
            )
            with self.assertRaises(URLFetchRestrictedError) as ctx:
                fetcher.fetch_job_url(f"https://careers.test.example:{port}/slow")
            self.assertEqual(ctx.exception.restriction_type, "NetworkError")

    def test_secondary_peer_defense_terminates_unauthorized_socket(self) -> None:
        """Secondary defense terminates connection immediately if peer IP is unauthorized."""
        class SimpleHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()

            def log_message(self, format, *args):
                pass

        port, _ = self._start_https_server(SimpleHandler)

        # In this test, we do NOT allow 127.0.0.1 in allow_test_ip!
        # When the adapter tries to connect to 127.0.0.1, the peer check must terminate with UnsafeURLError
        session = requests.Session()
        session.trust_env = False
        adapter = PinnedHTTPAdapter(pinned_ip="127.0.0.1")
        session.mount("https://", adapter)

        with self.assertRaises(UnsafeURLError) as ctx:
            session.get(f"https://careers.test.example:{port}/jobs", verify=self.ca_file)

        self.assertIn("peer IP '127.0.0.1' is private or restricted", str(ctx.exception))
        adapter.close()
        session.close()


if __name__ == "__main__":
    unittest.main()

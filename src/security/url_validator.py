"""URL Safety Validator and SSRF Defense Engine.

Guarantees that job listing URLs provided by users target valid, public,
routable destinations and prevent Server-Side Request Forgery (SSRF),
DNS rebinding, internal service discovery, and protocol abuse.
"""

import ipaddress
import re
import socket
from typing import List
import urllib.parse

from src.database.exceptions import UnsafeURLError
from src.utils.logger import setup_logger

logger = setup_logger("URLSafetyValidator")

ALLOWED_SCHEMES = {"http", "https"}

# Blocked hostnames, suffixes, and cloud metadata identifiers
BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
}

BLOCKED_DOMAIN_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home",
    ".onion",
    ".localhost",
)

# Custom private/restricted networks beyond standard ipaddress checks
EXTRA_BLOCKED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),     # Shared Address Space (Carrier-Grade NAT)
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # Documentation (TEST-NET-1)
    ipaddress.ip_network("198.51.100.0/24"),   # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),    # Documentation (TEST-NET-3)
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved for Future Use
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast
    ipaddress.ip_network("169.254.169.254/32"), # Cloud Metadata Endpoint
]


class URLSafetyValidator:
    """Validates destination safety against SSRF and private network access."""

    @classmethod
    def is_ip_private_or_restricted(cls, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Determines whether an IP address is private, loopback, link-local, or restricted."""
        # Standard library properties
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return True

        # Check against explicitly restricted network ranges
        for net in EXTRA_BLOCKED_NETWORKS:
            if ip in net:
                return True

        return False

    @classmethod
    def resolve_and_validate_hostname(cls, hostname: str, port: int = 80) -> List[str]:
        """Resolves hostname via DNS and asserts that all returned IP addresses are public.
        
        Prevents DNS rebinding and private IP resolution.
        """
        try:
            # socket.getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
            addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            raise UnsafeURLError(f"Unable to resolve domain '{hostname}': {e}")

        if not addr_info:
            raise UnsafeURLError(f"DNS resolution returned no records for domain '{hostname}'.")

        resolved_ips: List[str] = []
        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = str(sockaddr[0])
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                raise UnsafeURLError(f"Invalid resolved IP address: {ip_str}")

            if cls.is_ip_private_or_restricted(ip_obj):
                raise UnsafeURLError(
                    f"Access denied: Domain '{hostname}' resolves to private/restricted IP '{ip_str}'."
                )
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)

        return resolved_ips

    @classmethod
    def validate_url(cls, url: str) -> str:
        """Validates a user-supplied URL for scheme, format, destination safety, and SSRF defense.
        
        Returns:
            Normalized, safe URL string.
            
        Raises:
            UnsafeURLError: If the URL violates network boundary or scheme rules.
        """
        if not url or not isinstance(url, str):
            raise UnsafeURLError("URL must be a non-empty string.")

        clean_url = url.strip()
        if len(clean_url) > 2048:
            raise UnsafeURLError("URL length exceeds maximum limit of 2048 characters.")

        # Disallow control characters / whitespace in URL
        if re.search(r"[\x00-\x1f\x7f\s]", clean_url):
            raise UnsafeURLError("URL contains invalid control characters or whitespace.")

        parsed = urllib.parse.urlparse(clean_url)

        # 1. Scheme Validation
        if not parsed.scheme or parsed.scheme.lower() not in ALLOWED_SCHEMES:
            raise UnsafeURLError(
                f"Unsupported URL scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed."
            )

        # 2. Hostname Validation
        hostname = parsed.hostname
        if not hostname:
            raise UnsafeURLError("URL must contain a valid hostname.")

        hostname_lower = hostname.lower().strip(".")

        # Reject user:pass@host authentication credentials
        if parsed.username or parsed.password:
            raise UnsafeURLError("Embedded user credentials in URL are prohibited.")

        # Check explicitly blocked hostnames
        if hostname_lower in BLOCKED_HOSTNAMES:
            raise UnsafeURLError(f"Access to '{hostname}' is prohibited.")

        # Check blocked domain suffixes
        if any(hostname_lower.endswith(suffix) for suffix in BLOCKED_DOMAIN_SUFFIXES):
            raise UnsafeURLError(f"Access to private/local domain '{hostname}' is prohibited.")

        # 3. IP Literal Check
        is_literal_ip = False
        try:
            ip_obj = ipaddress.ip_address(hostname_lower)
            is_literal_ip = True
            if cls.is_ip_private_or_restricted(ip_obj):
                raise UnsafeURLError(
                    f"Access to private, loopback, or non-routable IP address '{hostname}' is prohibited."
                )
        except ValueError:
            # Not an IP literal, it is a domain name
            pass

        # 4. Port Check
        port = parsed.port
        if port is not None and port not in (80, 443, 8080, 8443):
            # Restrict to standard web ports
            raise UnsafeURLError(f"Non-standard web port '{port}' is prohibited.")

        # 5. DNS Resolution & Rebinding Check for domain names
        if not is_literal_ip:
            cls.resolve_and_validate_hostname(hostname_lower, port or (443 if parsed.scheme == "https" else 80))

        return clean_url

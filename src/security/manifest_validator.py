"""WebExtensions Match Pattern & Manifest Validator (RFC / Chrome / Safari Specification).

Implements the official WebExtensions Match Pattern Grammar:
<url-pattern> := <scheme>://<host><path>
<scheme> := '*' | 'http' | 'https' | 'file' | 'ftp' | 'urn'
<host> := '*' | '*.' <hostname-label>+ | <hostname-label>+
<path> := '/' <any chars>

Strictly enforces:
1. Wildcard placement: In <host>, '*' can only be the entire host ('*') or the first component followed by '.' ('*.domain.com').
2. Suffix wildcards like 'careers.*' or 'jobs.*' are STRICTLY INVALID.
3. Middle wildcards like 'sub.*.domain.com' or prefix wildcards like '*foo.com' are STRICTLY INVALID.
4. Missing path like 'https://example.com' (missing trailing slash/path) is STRICTLY INVALID.
5. Unsupported schemes like 'ssh://' or 'javascript://' are STRICTLY INVALID.
"""

import json
from pathlib import Path
import re
from typing import List, Tuple


class MatchPatternError(ValueError):
    """Raised when a WebExtension match pattern violates the official grammar."""
    pass


class WebExtensionMatchPatternValidator:
    """Validates WebExtension match patterns according to Chrome & Safari specs."""

    # Valid schemes for extension match patterns
    SUPPORTED_SCHEMES = {"http", "https", "file", "ftp", "urn", "*"}

    # Hostname label regex: alphanumeric + hyphen, cannot start or end with hyphen
    LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$")

    @classmethod
    def validate_pattern(cls, pattern: str) -> Tuple[bool, str]:
        """Validates a single WebExtensions match pattern string.

        Returns:
            Tuple[bool, str]: (is_valid, error_reason)
        """
        if not pattern or not isinstance(pattern, str):
            return (False, "Pattern must be a non-empty string.")

        clean = pattern.strip()

        # Special case: <all_urls>
        if clean == "<all_urls>":
            return (True, "")

        # Scheme separator check
        if "://" not in clean:
            return (False, f"Missing '://' scheme separator in pattern '{clean}'.")

        scheme, rest = clean.split("://", 1)

        # 1. Scheme validation
        if scheme not in cls.SUPPORTED_SCHEMES:
            return (False, f"Unsupported scheme '{scheme}' in pattern '{clean}'. Allowed: {cls.SUPPORTED_SCHEMES}")

        # 2. Path separation check
        if "/" not in rest:
            return (False, f"Missing path component in pattern '{clean}'. Must start with '/' after host.")

        slash_index = rest.index("/")
        raw_host = rest[:slash_index]
        path = rest[slash_index:]  # starts with '/'

        # 3. Path validation
        if not path.startswith("/"):
            return (False, f"Path must start with '/' in pattern '{clean}'.")

        # 4. Host validation for file scheme
        if scheme == "file":
            if raw_host != "":
                return (False, f"For 'file' scheme, host must be empty: '{clean}'.")
            return (True, "")

        # 5. Host validation for network schemes
        if not raw_host:
            return (False, f"Host cannot be empty for scheme '{scheme}' in pattern '{clean}'.")

        # Handle optional port (e.g. localhost:3000, 127.0.0.1:8000)
        if ":" in raw_host:
            host_parts = raw_host.split(":")
            if len(host_parts) != 2:
                return (False, f"Invalid port specification in host '{raw_host}'.")
            host, port_str = host_parts
            if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
                return (False, f"Invalid port '{port_str}' in host '{raw_host}'.")
        else:
            host = raw_host

        # Single wildcard host
        if host == "*":
            return (True, "")

        # Wildcard placement validation
        if "*" in host:
            # Wildcard can ONLY be at the very start followed immediately by a dot: "*."
            if not host.startswith("*."):
                return (
                    False,
                    f"Invalid wildcard placement in host '{host}'. "
                    f"Wildcard '*' can only be the whole host ('*') or leading wildcard subdomain ('*.example.com'). "
                    f"Suffix wildcards like 'careers.*' or 'jobs.*' are invalid.",
                )

            # Check that there are no additional wildcards in the rest of the host
            sub_host = host[2:]
            if "*" in sub_host:
                return (False, f"Multiple wildcards in host '{host}' are invalid.")

            if not sub_host:
                return (False, f"Trailing dot after wildcard '*.' with no domain in '{clean}'.")

            labels = sub_host.split(".")
        else:
            labels = host.split(".")

        # Validate each domain label
        for label in labels:
            if not label:
                return (False, f"Empty domain label in host '{host}'.")
            # IPv4 or alphanumeric domain check
            if not cls.LABEL_REGEX.match(label):
                return (False, f"Invalid domain label '{label}' in host '{host}'.")

        # TLD cannot be purely numeric unless it's a valid IPv4 address
        if len(labels) == 4 and all(l.isdigit() for l in labels):
            # IPv4 host
            try:
                parts = [int(l) for l in labels]
                if not all(0 <= p <= 255 for p in parts):
                    return (False, f"IPv4 octet out of range in '{host}'.")
            except ValueError:
                return (False, f"Invalid IPv4 host in '{host}'.")
        elif labels[-1].isdigit() and len(labels) > 1:
            return (False, f"Top-level domain cannot be numeric in '{host}'.")

        return (True, "")

    @classmethod
    def validate_manifest(cls, manifest_path: Path) -> List[str]:
        """Validates all match patterns and host permissions in a manifest.json file.

        Returns:
            List[str]: List of validation errors encountered (empty if valid).
        """
        errors: List[str] = []
        if not manifest_path.exists():
            return [f"Manifest file does not exist: {manifest_path}"]

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return [f"Failed to parse manifest JSON at {manifest_path}: {e}"]

        # 1. Validate host_permissions
        for hp in data.get("host_permissions", []):
            is_valid, reason = cls.validate_pattern(hp)
            if not is_valid:
                errors.append(f"Invalid host_permission '{hp}': {reason}")

        # 1b. Validate optional_host_permissions
        for ohp in data.get("optional_host_permissions", []):
            is_valid, reason = cls.validate_pattern(ohp)
            if not is_valid:
                errors.append(f"Invalid optional_host_permission '{ohp}': {reason}")

        # 2. Validate content_scripts matches
        for cs_idx, cs in enumerate(data.get("content_scripts", [])):
            for match in cs.get("matches", []):
                is_valid, reason = cls.validate_pattern(match)
                if not is_valid:
                    errors.append(f"Content script #{cs_idx} invalid match '{match}': {reason}")

            for exc in cs.get("exclude_matches", []):
                is_valid, reason = cls.validate_pattern(exc)
                if not is_valid:
                    errors.append(f"Content script #{cs_idx} invalid exclude_match '{exc}': {reason}")

        return errors

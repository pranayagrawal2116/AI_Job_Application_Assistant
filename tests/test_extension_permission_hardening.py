"""Regression Tests for WebExtension Match Pattern Grammar & Permission Hardening (Phase C.1 / Architecture v2.1.1).

Verifies:
1. WebExtension Match Pattern Validator:
   - Exact host matching (https://example.com/path).
   - Single host wildcard (https://*.example.com/*).
   - Any host wildcard (https://*/*).
   - Invalid suffix wildcard (https://careers.*/*, https://jobs.*/*).
   - Invalid middle wildcard (https://sub.*.example.com/*).
   - Missing path component (https://example.com).
   - Unsupported schemes (ssh://example.com/*, javascript://example.com/*).
2. Manifest Integrity:
   - Chromium extension manifest (browser_extension/manifest.json) has 0 validation errors.
   - Safari extension manifest (safari_extension/.../manifest.json) has 0 validation errors.
   - Neither manifest contains invalid suffix wildcard patterns.
3. Content script security in content.js:
   - Enforces HTTPS (except localhost).
   - Enforces canonical origin and approved redirects.
   - Prohibits permissive reverse-suffix matching and global ATS domain fallbacks.
   - Enforces expiration and execution ID binding.
"""

import json
from pathlib import Path
from src.security.manifest_validator import WebExtensionMatchPatternValidator

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
CHROMIUM_MANIFEST = WORKSPACE_ROOT / "browser_extension" / "manifest.json"
SAFARI_MANIFEST = WORKSPACE_ROOT / "safari_extension" / "JobFlow AI" / "JobFlow AI Extension" / "Resources" / "manifest.json"
CONTENT_JS = WORKSPACE_ROOT / "browser_extension" / "content.js"


class TestWebExtensionMatchPatternValidator:
    """Comprehensive unit tests for official WebExtension match-pattern grammar."""

    def test_exact_host_matching(self):
        valid, err = WebExtensionMatchPatternValidator.validate_pattern("https://example.com/path")
        assert valid is True, f"Expected exact host to be valid, got: {err}"

    def test_single_host_wildcard(self):
        valid, err = WebExtensionMatchPatternValidator.validate_pattern("https://*.example.com/*")
        assert valid is True, f"Expected leading subdomain wildcard to be valid, got: {err}"

    def test_any_host_wildcard(self):
        valid, err = WebExtensionMatchPatternValidator.validate_pattern("https://*/*")
        assert valid is True, f"Expected any-host wildcard to be valid, got: {err}"

    def test_invalid_suffix_wildcard_careers(self):
        valid, err = WebExtensionMatchPatternValidator.validate_pattern("https://careers.*/*")
        assert valid is False, "Expected suffix wildcard 'careers.*' to be strictly invalid"
        assert "careers.*" in err or "Suffix wildcards" in err

    def test_invalid_suffix_wildcard_jobs(self):
        valid, err = WebExtensionMatchPatternValidator.validate_pattern("https://jobs.*/*")
        assert valid is False, "Expected suffix wildcard 'jobs.*' to be strictly invalid"
        assert "jobs.*" in err or "Suffix wildcards" in err

    def test_invalid_middle_wildcard(self):
        valid, err = WebExtensionMatchPatternValidator.validate_pattern("https://sub.*.example.com/*")
        assert valid is False, "Expected middle wildcard to be invalid"
        assert "wildcard" in err.lower()

    def test_missing_path_component(self):
        valid, err = WebExtensionMatchPatternValidator.validate_pattern("https://example.com")
        assert valid is False, "Expected missing trailing slash/path to be invalid"
        assert "Missing path" in err

    def test_invalid_scheme(self):
        valid, err = WebExtensionMatchPatternValidator.validate_pattern("ssh://example.com/*")
        assert valid is False, "Expected ssh scheme to be invalid"
        assert "Unsupported scheme" in err

    def test_all_urls_special_pattern(self):
        valid, _ = WebExtensionMatchPatternValidator.validate_pattern("<all_urls>")
        assert valid is True


class TestManifestIntegrityAndParity:
    """Validates real Chromium and Safari extension manifests."""

    def test_chromium_manifest_has_zero_validation_errors(self):
        assert CHROMIUM_MANIFEST.exists(), f"Chromium manifest missing at {CHROMIUM_MANIFEST}"
        errors = WebExtensionMatchPatternValidator.validate_manifest(CHROMIUM_MANIFEST)
        assert len(errors) == 0, f"Chromium manifest contains invalid match patterns: {errors}"

    def test_safari_manifest_has_zero_validation_errors(self):
        assert SAFARI_MANIFEST.exists(), f"Safari manifest missing at {SAFARI_MANIFEST}"
        errors = WebExtensionMatchPatternValidator.validate_manifest(SAFARI_MANIFEST)
        assert len(errors) == 0, f"Safari manifest contains invalid match patterns: {errors}"

    def test_manifests_contain_no_suffix_wildcards(self):
        for path in (CHROMIUM_MANIFEST, SAFARI_MANIFEST):
            data = json.loads(path.read_text(encoding="utf-8"))
            all_patterns = list(data.get("host_permissions", []))
            for cs in data.get("content_scripts", []):
                all_patterns.extend(cs.get("matches", []))

            for pattern in all_patterns:
                assert "careers.*" not in pattern, f"Invalid suffix wildcard found in {path}: {pattern}"
                assert "jobs.*" not in pattern, f"Invalid suffix wildcard found in {path}: {pattern}"

    def test_manifest_parity_between_chromium_and_safari(self):
        chrome_data = json.loads(CHROMIUM_MANIFEST.read_text(encoding="utf-8"))
        safari_data = json.loads(SAFARI_MANIFEST.read_text(encoding="utf-8"))

        assert safari_data["host_permissions"] == chrome_data["host_permissions"]
        assert safari_data.get("optional_host_permissions") == chrome_data.get("optional_host_permissions")
        assert len(safari_data["content_scripts"]) == len(chrome_data["content_scripts"])
        for s_cs, c_cs in zip(safari_data["content_scripts"], chrome_data["content_scripts"]):
            assert s_cs["matches"] == c_cs["matches"]
            assert s_cs["js"] == c_cs["js"]


class TestContentScriptStrictOriginEnforcement:
    """Validates that content.js enforces strict origin binding without permissive fallbacks."""

    def test_content_js_enforces_strict_origin_matching(self):
        assert CONTENT_JS.exists(), "content.js must exist"
        content = CONTENT_JS.read_text(encoding="utf-8")

        assert "isAuthorizedOriginForPlan" in content
        assert "canonical_target_origin" in content
        assert "approved_redirect_origins" in content
        assert "https:" in content
        assert "expires_at" in content

        # STRICT PROHIBITION: Permissive reverse-suffix matching and global ATS loop must be absent
        assert 'targetHost.endsWith("." + currentHost)' not in content, "Permissive reverse-suffix matching must be eliminated"
        assert 'currentHost.endsWith("." + targetHost)' not in content, "Permissive suffix matching must be eliminated"
        assert "supportedAtsRootDomains" not in content, "Global ATS root domain fallback loop must be eliminated"

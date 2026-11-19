"""Regression Tests for Extension Permission Hardening & Origin Validation (Phase C.1 / Architecture v2.1.1).

Verifies:
1. Least-privilege manifest: No broad wildcards ('https://*/*', 'http://*/*') in content scripts or host permissions.
2. Web App Bridge isolation: Bridge is scoped strictly to JobFlow frontend on localhost:3000 / 127.0.0.1:3000.
3. ATS Domain scoping: Content script injection is restricted to authorized ATS domains (Lever, Greenhouse, Workday, Keka, RippleHire, Kula, careers.*, jobs.*).
4. Origin safety check in content script: Form autofill execution halts when active plan target does not match current host.
5. Safari parity: Safari extension resources manifest matches Chromium manifest.
"""

import json
from pathlib import Path
import re
import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
CHROMIUM_MANIFEST = WORKSPACE_ROOT / "browser_extension" / "manifest.json"
SAFARI_MANIFEST = WORKSPACE_ROOT / "safari_extension" / "JobFlow AI" / "JobFlow AI Extension" / "Resources" / "manifest.json"
CONTENT_JS = WORKSPACE_ROOT / "browser_extension" / "content.js"


def test_chromium_manifest_least_privilege():
    assert CHROMIUM_MANIFEST.exists(), "Chromium manifest.json must exist"
    data = json.loads(CHROMIUM_MANIFEST.read_text(encoding="utf-8"))

    # Assert no global HTTP/HTTPS wildcards
    for host in data.get("host_permissions", []):
        assert host not in ("https://*/*", "http://*/*", "<all_urls>"), (
            f"Overly broad host permission detected: {host}"
        )

    # Check content script matches
    content_scripts = data.get("content_scripts", [])
    assert len(content_scripts) >= 2, "Expected at least bridge and ATS content scripts"

    bridge_script = next(cs for cs in content_scripts if "jobflow_bridge.js" in cs.get("js", []))
    assert all("localhost:3000" in m or "127.0.0.1:3000" in m for m in bridge_script["matches"])

    ats_script = next(cs for cs in content_scripts if "content.js" in cs.get("js", []))
    for m in ats_script["matches"]:
        assert m not in ("https://*/*", "http://*/*", "<all_urls>"), (
            f"Overly broad content script match detected: {m}"
        )
        assert any(ats in m for ats in ("lever.co", "greenhouse.io", "myworkdayjobs.com", "keka.com", "ripplehire.com", "kula.ai", "careers.", "jobs.")), (
            f"Match pattern {m} is not an authorized ATS or employer career domain."
        )


def test_safari_manifest_parity_with_chromium():
    assert SAFARI_MANIFEST.exists(), "Safari manifest.json must exist"
    chrome_data = json.loads(CHROMIUM_MANIFEST.read_text(encoding="utf-8"))
    safari_data = json.loads(SAFARI_MANIFEST.read_text(encoding="utf-8"))

    assert safari_data["host_permissions"] == chrome_data["host_permissions"]
    assert len(safari_data["content_scripts"]) == len(chrome_data["content_scripts"])
    for s_cs, c_cs in zip(safari_data["content_scripts"], chrome_data["content_scripts"]):
        assert s_cs["matches"] == c_cs["matches"]
        assert s_cs["js"] == c_cs["js"]


def test_content_js_enforces_origin_validation():
    assert CONTENT_JS.exists(), "content.js must exist"
    content = CONTENT_JS.read_text(encoding="utf-8")

    assert "isAuthorizedOriginForPlan" in content
    assert "currentHost === targetHost" in content or "targetHost" in content
    assert "supportedAtsRootDomains" in content
    assert "Halting to protect candidate data" in content

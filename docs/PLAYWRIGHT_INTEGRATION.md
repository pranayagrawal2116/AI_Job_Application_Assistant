# Playwright MCP Integration Guide

This document describes the architectural boundary, tool calling protocol, error handling strategies, and data ingestion pipeline connecting the Antigravity Agent with the Playwright MCP Server and the Python backend.

---

## 1. Architectural Boundary

```
┌────────────────────────────────────────────────────────┐
│                   Antigravity Agent                    │
│  - Invokes Playwright MCP tools                        │
│  - Reads accessibility tree snapshots (YAML)           │
│  - Locates semantic elements (headings, textboxes, links)│
│  - Extracts candidate job postings                     │
│  - Prepares ExtractedJobPayload                        │
└───────────────────────────┬────────────────────────────┘
                            │
               AgentIntegrationContract
                            │
┌───────────────────────────▼────────────────────────────┐
│                    Python Backend                      │
│  - DataValidator: sanitization, anti-bot detection     │
│  - DatabaseManager: deduplication check                │
│  - JobMatcher: 100-pt scoring & eligibility engine     │
│  - SQLite Database: persistent storage & audit logs    │
└────────────────────────────────────────────────────────┘
```

> **Separation of Concerns:** Python does not directly invoke Antigravity MCP tools. The Antigravity Agent drives the browser using connected MCP tools and communicates with the Python application via the [`AgentIntegrationContract`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/src/scraper/agent_integration_contract.py).

---

## 2. Playwright MCP Tool Calling Protocol

| Tool Name | Primary Purpose | When to Use |
| :--- | :--- | :--- |
| `browser_navigate` | Opens URL in the active tab | Starting page visits, navigation to job postings |
| `browser_snapshot` | Captures YAML accessibility tree | **Primary inspection tool** (inspect text, links, form refs) |
| `browser_click` | Performs mouse click on element | Clicking buttons, checkboxes, tabs, or links |
| `browser_type` | Types text into editable inputs | Entering search queries or form data (supports `submit: true`) |
| `browser_take_screenshot` | Saves visual viewport / fullpage | **Visual verification only** (e.g. proof of interaction) |
| `browser_tabs` | Manages browser tabs (`list`/`select`/`close`) | Multi-tab tracking and window focus |
| `browser_close` | Terminates active browser sessions | **Mandatory cleanup** at the end of workflows |

### Golden Rule: Accessibility-First Interaction
Prefer `browser_snapshot` over visual screenshot parsing. The accessibility tree provides deterministic semantic element references (`ref=...`), roles (`textbox`, `button`, `link`), and states (`checked`, `active`, `disabled`), preventing ambiguity.

---

## 3. Comprehensive Error Handling Matrix

| Error Scenario | Detection Signature | Mitigation / Recovery Procedure |
| :--- | :--- | :--- |
| **Navigation Timeout** | `browser_navigate` hangs or raises timeout | Cleanly abort, retry once after 5s delay. If persistent, record site unavailability. |
| **Missing Elements** | Element reference not found in snapshot | Re-capture snapshot with `browser_snapshot` to refresh stale refs. |
| **Stale Page References** | Ref IDs invalid after DOM mutation | Re-run `browser_snapshot` to acquire newly minted references. |
| **Unexpected Redirects** | Snapshot URL differs from target URL | Inspect redirected URL. If redirected to login wall or homepage, abort and record. |
| **Empty Snapshot** | Snapshot returns empty YAML | Verify tab focus using `browser_tabs(action='list')` and select active tab. |
| **Cloudflare / Bot Challenge** | Title contains "Just a moment...", "Attention Required" | **NEVER bypass.** Abort extraction, flag `is_restricted=True`, log official URL. |
| **CAPTCHA Encountered** | Snapshot contains "hCaptcha", "reCAPTCHA", "security check" | **NEVER attempt bypass.** Abort immediately, notify user, provide manual job link. |
| **Login Wall / Auth Required** | Snapshot prompts "Sign in to LinkedIn" or "Log in to view" | Do not attempt credential stuffing. Mark `is_restricted=True` and surface official URL. |
| **Browser Crash / Closure** | Tool returns "No open tabs" | Cleanly invoke `browser_navigate` to launch fresh browser context. |

---

## 4. End-to-End Ingestion Flow

1. **Navigate & Extract:** Agent calls `browser_navigate` and `browser_snapshot`.
2. **Assemble Payload:** Agent compiles extracted fields into [`ExtractedJobPayload`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/src/scraper/extraction_schema.py).
3. **Validate:** Python [`DataValidator`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/src/scraper/data_validator.py) cleans text, normalizes URLs, and detects anti-automation.
4. **Deduplicate:** [`DatabaseManager`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/src/database/db_manager.py) verifies URL and company+title uniqueness.
5. **Evaluate:** [`JobMatcher`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/src/matcher/job_matcher.py) computes 100-pt score, eligibility (`ELIGIBLE`/`INELIGIBLE`/`UNKNOWN`), and explanations.
6. **Store:** Persisted to SQLite with status `Discovered` and audit trail.


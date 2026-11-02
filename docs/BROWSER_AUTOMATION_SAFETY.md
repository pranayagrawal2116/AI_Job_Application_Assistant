# Browser Automation Safety & Ethical Operating Protocol

> **Mandatory Guidelines:** Applies to all automated browser sessions, scraping routines, and application workflows within the **AI Job Application Assistant**.

---

## 1. Zero Automated Submission Policy

- **Non-Negotiable Rule:** Applications are **NEVER submitted automatically**.
- In Phase 7, form filling automation will pause immediately prior to the final submission button (e.g., "Submit Application", "Apply Now", "Send").
- Transitioning any application to `Applied` strictly requires an explicit human authorization audit record via [`db.record_human_approval()`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/src/database/db_manager.py). Automated agents, bots, or matchers are forbidden from self-authorizing submissions.

---

## 2. Respect for Platform Restrictions & Anti-Automation Controls

1. **No CAPTCHA / Bot Bypass:**
   - Under no circumstances will the assistant attempt to bypass CAPTCHAs, Cloudflare Turnstile, Arkose Labs challenges, or device fingerprinting.
   - If an anti-automation challenge is encountered, the session must cleanly abort, log the restriction reason, and present the official application link for manual candidate review.

2. **Polite Rate Limiting:**
   - Adhere strictly to configured platform delays (minimum 3–5 seconds between page requests).
   - Never generate concurrent request floods or rapid-fire scraping bursts.

3. **Robots.txt & Terms of Service:**
   - Honor `robots.txt` exclusion directives.
   - Restrict discovery to publicly indexed, permitted job board sections.

4. **Authentication & Session Boundaries:**
   - Never inject hardcoded credentials, spoof authentication cookies, or store passwords in code.
   - Never harvest private member profiles or non-job-related platform data.

---

## 3. Candidate Privacy & Data Security

1. **Zero Fabrication:**
   - Never fabricate candidate experience, skills, projects, or grades to satisfy a job posting.
   - If a job demands skills the candidate lacks, mark them as missing.

2. **Local Storage Only:**
   - All extracted jobs, candidate profile data, and SQLite databases remain local on the user's filesystem and are excluded from Git by [`.gitignore`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/.gitignore).
   - Candidate resumes (`data/resumes/`) are never uploaded or transmitted to unapproved third-party servers.

---

## 4. Operational Checklist Before Launching Browser Tasks

- [x] Target URL is public and harmless.
- [x] Anti-automation detection handlers are active.
- [x] Human authorization requirement is enforced.
- [x] Browser session cleanup (`browser_close`) is guaranteed in `finally` blocks.


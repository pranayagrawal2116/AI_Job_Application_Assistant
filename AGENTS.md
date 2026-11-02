# AGENTS.md — Development Guidelines & Safety Protocol

> **Target Audience:** All AI agents, automated development assistants, and contributors working on the **AI Job Application Assistant** codebase.

---

## 1. Core Operating Principles

1. **Candidate Truthfulness (Zero Hallucination Policy):**
   - **NEVER** fabricate, infer, or embellish candidate experience, skills, certifications, degrees, grades, or project outcomes.
   - The candidate profile is rooted in verifiable data. If information is missing, leave the field empty or clearly flagged as pending user input.
   - **Crucial Rule:** Always prompt the candidate to provide their latest resume file (PDF or DOCX in `data/resumes/`) before extracting or utilizing personal details in application preparation.

2. **Strict Human-in-the-Loop Application Approval:**
   - **NEVER submit any job application automatically.**
   - All browser automation workflows MUST pause immediately prior to the final submission action (e.g., clicking "Submit Application", "Apply Now", or "Send").
   - The user must explicitly inspect the populated fields, review any generated cover letter, and manually authorize or execute the final submission.

3. **Browser Automation & Anti-Automation Ethics:**
   - Always leverage the connected **Playwright MCP Server** via MCP tool calls (`browser_navigate`, `browser_snapshot`, `browser_click`, `browser_fill_form`, etc.).
   - Do **NOT** spin up duplicate standalone browser automation systems or raw unmanaged driver processes unless specifically instructed.
   - **Respect Terms of Service, Robots Restrictions, and Anti-Automation Controls:**
     - Do **NOT** attempt to bypass CAPTCHAs, bot detections (Cloudflare, PerimeterX, Arkose), or two-factor authentication.
     - Implement human-like rate limiting (minimum 2–5 seconds between requests).
     - If a site blocks, rate-limits, or restricts automated access, cleanly abort the automated extraction, notify the user with an informative log message, and present the official job URL for manual inspection.

4. **Security, Secrets, and Privacy:**
   - **Zero Secrets in Code:** Never commit or hard-code API keys, credentials, session tokens, passwords, or cookies.
   - All credentials and environment flags belong in `.env` (referenced via `.env.example`).
   - Candidate resumes (`data/resumes/`), database records (`data/storage/`), and exports (`data/exports/`) are strictly kept local and git-ignored.
   - Never transmit candidate data or resume files to unapproved third-party servers.

---

## 2. Technical Stack & Conventions

- **Language:** Python 3.11+ (Python 3.13 compatible).
- **Dashboard:** Streamlit.
- **Data Persistence:** SQLite (`data/storage/job_assistant.db`) accessed via standard `sqlite3` or lightweight query managers.
- **Data Analysis:** Pandas for tabular manipulation, deduplication, and CSV export.
- **Configuration:** YAML (`config/config.yaml`, `config/scoring_rules.yaml`) and JSON (`config/search_criteria.json`, `data/profile/candidate_profile.json`).
- **Browser Automation:** Playwright MCP tools.

---

## 3. Matching & Scoring Rules (Phase 3 Spec)

- **Total Score:** 100 points
  - **Domain Relevance:** 30 pts (AI, ML, Deep Learning, GenAI, Data Science, NLP, CV, Python)
  - **Technical Skills:** 25 pts (Python, ML, Data Preprocessing, Data Visualization, Flutter/Dart)
  - **Educational Eligibility:** 20 pts (CS with AI & DS, 2028 graduation; candidate CGPA 7.6 evaluated strictly against explicit employer cutoff — no deduction if no cutoff specified)
  - **Experience Compatibility:** 10 pts (Student/Fresher roles: 10 pts; >1-2 years: penalty)
  - **Location Preference:** 10 pts (India / Remote / Work from Home: 10 pts)
  - **Duration Compatibility:** 5 pts (Standard summer/winter or flexible part-time)

- **Classifications:**
  - `85 – 100`: Excellent match
  - `70 – 84`: Good match
  - `50 – 69`: Moderate match
  - `< 50`: Low match

- **Mandatory Disqualification Override:**
  - If a mandatory requirement fails (e.g. requires 3+ years experience, requires graduation before 2026, employer explicitly mandates higher minimum CGPA, or mandates in-person work in an unsupported country), the engine **MUST** explicitly mark `is_eligible: false`, irrespective of high skill/keyword scores.
  - The evaluation output must always display the breakdown and specific reason behind every deduction or disqualification.
  - Mandatory eligibility checks operate independently of the 0-100 numerical matching score.

---

## 4. Application State Machine (Phase 2 & 6 Spec)

Every tracked job posting transitions through discrete statuses:
```
Discovered -> Under Review -> Shortlisted -> Application Prepared -> Awaiting Approval -> Applied -> (Interview | Rejected | Withdrawn)
```
- **Submission Safeguard:** An application status CANNOT be transitioned to `Applied` without explicit user confirmation.
- **Deduplication:** The database MUST enforce uniqueness on normalized job URLs and composite `(company_name, job_title)` to prevent duplicate listings or re-applying.

---

## 5. Playwright MCP Tooling Protocol

When interacting with the browser via Playwright MCP:
1. Call `browser_navigate` with the target URL.
2. Read the page accessibility tree or state using `browser_snapshot`.
3. Locate elements by ref or semantic selectors.
4. Interact using `browser_fill_form`, `browser_click`, or `browser_type`.
5. Capture visual evidence when helpful using `browser_take_screenshot`.
6. Always clean up tabs or close sessions with `browser_close` when operations conclude.

---

## 6. Phased Implementation Roadmap

- [x] **Phase 1: Project Initialization & Safety Architecture**
  - Workspace scaffolding, configs, candidate profile templates, Playwright MCP verification, README & AGENTS.md.
- [x] **Phase 2: SQLite Storage & Job Management Engine** (Complete)
  - Database schema, models, CRUD operations, deduplication logic, application status tracking, transactions, backup/restore, CSV export.
- [x] **Phase 3: Job Matching & Eligibility Evaluation Engine** (Complete)
  - Multi-factor scoring algorithm (100 pts), disqualification logic, transparent explanation generator, explicit human audit approval gate.
- [x] **Phase 4: Playwright MCP Automation Module** (Complete)
  - Robust navigation routines, accessibility tree interpretation, form inspection, anti-automation detection handler, agent-backend integration contract.
- [x] **Phase 5: Modular Job Discovery Scrapers** (Complete)
  - Modular adapters for LinkedIn, Internshala, Indeed, Naukri, and Company Career ATS (Greenhouse/Lever) feeds.
  - Anti-automation defense detection (Cloudflare Turnstile, login wall, Akamai) with graceful restriction logging and URL preservation.
  - Automated deduplication, real-time Phase 3 matching and eligibility evaluation, SQLite persistence, and CSV export.
- [x] **Phase 6: Streamlit Interactive Dashboard** (Complete)
  - Professional 8-page responsive UI: Overview, Explore Jobs, Shortlisted Jobs, Application Tracker, Job Matching Analytics, Discovery Management, Candidate Profile, Settings.
  - Multi-dimensional filtering, deep score inspection with 6-factor score breakdowns, shortlist management, status transitions with strict human-in-the-loop audit gate for 'Applied' status.
  - Interactive Plotly visualizations (score distribution, eligibility donut, location & platform charts, employer skill demand vs candidate gap analysis, application funnel).
  - SQLite database management with atomic live online backup, snapshot restore, and full CSV export.
  - Candidate profile editor with SQLite version history snapshots.
  - Verified with 7 automated unit tests (64 total suite tests passing) and Playwright MCP browser snapshot & screenshot verification.
- [x] **Phase 7: Application Preparation & Approval Workflow** (Complete)
  - Zero-hallucination resume parser supporting PDF and DOCX (`ResumeParser`).
  - Candidate profile synchronizer with immutable SQLite snapshots (`ProfileUpdater`, verified: 3 months at Sarita Infotech Pvt. Ltd. as Project Manager | Mobile App Development; Python, JavaScript, C/C++; Medical Chatbot; Sarita ABDM; CGPA 7.6, Class of 2028).
  - Resume-job alignment and transparent gap analyzer (`ResumeJobMatcher`).
  - Personalized, professional tailored cover letter generator saving individual markdown letters to disk (`CoverLetterGenerator`).
  - Screening question response drafter with strict `NEEDS CANDIDATE INPUT` tagging for unverified queries (`QuestionAnswerer`).
  - Playwright form pre-filling payload planner and anti-automation safeguard (`FormPrefiller`).
  - Strict human-in-the-loop review packet and authorization gate preventing automated submissions (`HumanApprovalGate`).
  - Interactive Streamlit Application Preparer interface (Resume Manager, Alignment Inspector, Cover Letter Editor, Screening QA, Human Approval Gate, and Prepared Application History).
  - Verified with 9 new automated unit tests (73 total suite tests passing) and Playwright MCP browser snapshot & screenshot verification.

---

## 7. Approval Requirement

> **STOP:** Never jump to subsequent phases without explicit user instruction and approval of the completed phase deliverables.


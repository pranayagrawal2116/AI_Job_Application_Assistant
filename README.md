# AI Job Application Assistant

A professional, ethical, and modular assistant designed to discover, evaluate, shortlist, and prepare job applications for **AI and Machine Learning internships** across India and remote markets.

---

## 🎯 Target Opportunities & Focus

- **Roles:**
  - AI Intern
  - Machine Learning Intern
  - Data Science Intern
  - Python Developer Intern
  - Deep Learning Intern
  - Generative AI Intern
  - NLP Intern
  - Computer Vision Intern
- **Geographic Preferences:** India, Remote, and Work-from-Home opportunities.
- **Experience Level:** Student, Fresher, Entry-level internships (Graduating 2028).

---

## 👤 Candidate Profile (Configured & Editable)

- **Education:** MIT World Peace University (Pune, India)
- **Degree:** B.Tech in Computer Science Engineering – Artificial Intelligence & Data Science
- **Expected Graduation:** 2028
- **Current CGPA:** 7.6
- **Technical Interests:** Python, Machine Learning, Artificial Intelligence, Data Science, Data Preprocessing, Data Visualization, Flutter development
- **Projects:**
  - *Hospital Management Application*
  - *Factory Management Application*
  - *Diabetes Risk Prediction using Machine Learning*
- **Experience:** Fresher / Entry-Level Student (No unverified employment added)
- **Profile Files:** Available in editable YAML ([`candidate_profile.yaml`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/data/profile/candidate_profile.yaml)) and JSON ([`candidate_profile.json`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/data/profile/candidate_profile.json)).

> [!IMPORTANT]
> **Zero Fabrication Policy:** Missing information, work history, achievements, and certifications are never invented. Please drop your latest resume (PDF/DOCX) in `data/resumes/` before running real application preparation workflows.

---

## 🛠️ Technology Stack

- **Core Backend:** Python 3.11+ / Python 3.13
- **User Interface:** Streamlit interactive dashboard
- **Data Persistence:** SQLite (`job_assistant.db`)
- **Data Manipulation:** Pandas & NumPy
- **Configurations:** YAML (`config.yaml`, `scoring_rules.yaml`) and JSON (`search_criteria.json`)
- **Browser Automation:** Playwright via connected Playwright MCP server

---

## 📁 Project Directory Structure

```
AI_Job_Application_Assistant/
├── config/
│   ├── config.yaml              # Main configuration (app settings, platform toggles, rate limits)
│   ├── scoring_rules.yaml       # 100-point matching weights, thresholds, and eligibility rules
│   └── search_criteria.json     # Search terms, keywords, target platforms, and negative filters
├── data/
│   ├── profile/
│   │   ├── candidate_profile.yaml  # Primary editable candidate profile
│   │   └── candidate_profile.json  # Machine-readable candidate profile
│   ├── resumes/                 # Storage for user-provided resumes (git-ignored)
│   ├── storage/                 # Local SQLite database files (git-ignored)
│   └── exports/                 # Dashboard CSV exports (git-ignored)
├── src/
│   ├── __init__.py
│   ├── config.py                # Configuration & profile loader utility
│   ├── database/                # SQLite schema and models (Phase 2)
│   │   ├── __init__.py
│   │   └── schema.sql           # Initial database schema
│   ├── matcher/                 # 100-point job matching engine (Phase 3)
│   │   └── __init__.py
│   ├── scraper/                 # Job discovery & Playwright MCP integration (Phases 4 & 5)
│   │   └── __init__.py
│   ├── preparer/                # Resume parser, job matcher, cover letter & approval engine (Phase 7)
│   │   ├── __init__.py
│   │   ├── resume_parser.py     # PDF & DOCX zero-hallucination parser
│   │   ├── profile_updater.py   # Canonical profile & SQLite snapshot synchronizer
│   │   ├── resume_matcher.py    # Opportunity-to-resume alignment & gap analysis
│   │   ├── cover_letter_generator.py # Tailored cover letter drafter
│   │   ├── question_answerer.py # Screening QA generator with unverified tags
│   │   ├── form_prefiller.py    # Playwright form mapping & anti-bot safety
│   │   └── approval_gate.py     # Strict human review packet & authorization gate
│   └── utils/
│       ├── __init__.py
│       └── logger.py            # Centralized logging configuration
├── dashboard/
│   ├── __init__.py
│   ├── app.py                   # Streamlit multi-page dashboard application (Phase 6)
│   ├── components/              # Modular UI components (metric cards, score breakdown, job cards, filters)
│   ├── services/                # Backend data services & Plotly analytics engine
│   └── views/                   # 8 Page views (overview, explore, shortlist, tracker, analytics, discovery, profile, settings)
├── tests/
│   ├── __init__.py
│   ├── test_config.py           # Unit tests for configuration and profile validation
│   └── test_playwright_mcp.py   # Verification script for Playwright MCP
├── .env.example                 # Environment template
├── .gitignore                   # Secrets and local privacy exclusion rules
├── AGENTS.md                    # Agent operating principles & safety protocol
├── requirements.txt             # Project dependencies
└── README.md                    # Project overview & documentation
```

---

## ⚖️ 100-Point Job Matching Engine

Every job posting is evaluated across 6 objective dimensions:

| Dimension | Max Points | Evaluation Scope |
| :--- | :---: | :--- |
| **Domain Relevance** | 30 | AI, ML, GenAI, Data Science, NLP, CV, Python |
| **Technical Skill Match** | 25 | Alignment with candidate's Python, ML, Flutter, Data skills |
| **Educational Eligibility** | 20 | Degree match (CSE AI & DS), graduation 2028, CGPA 7.6 |
| **Experience Compatibility** | 10 | Explicitly for students/freshers vs. years demanded |
| **Location Preference** | 10 | Remote / Work-from-Home / India (Pune, Bengaluru, etc.) |
| **Duration Compatibility** | 5 | Flexible/summer/winter internship vs. rigid full-time |

### Classification Tiers:
- **85 – 100 Points:** Excellent Match *(Top priority for application)*
- **70 – 84 Points:** Good Match *(Recommended for review)*
- **50 – 69 Points:** Moderate Match *(Secondary)*
- **Below 50 Points:** Low Match *(Filtered out)*

> [!NOTE]
> **Strict Eligibility Rule:** If a mandatory requirement is violated (e.g., job strictly demands 3+ years experience, requires immediate graduation before 2026, or mandates in-person work in an unsupported country), the candidate is marked **Ineligible**, regardless of raw score.

---

## 🛡️ Safety, Security, and Compliance

1. **Human-in-the-Loop Safeguard:** Applications are **never submitted automatically**. Automation always stops at the review screen before the final click.
2. **Platform Respect:** Respects `robots.txt`, authentication requirements, and rate limits. Never bypasses CAPTCHA or security controls; provides direct official application links if a platform restricts automated access.
3. **Local Privacy:** Resumes, contact details, application histories, and notes remain on your local machine and are excluded by `.gitignore`.

---

## 🚀 Getting Started

### 1. Environment Setup
```bash
# Activate your virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
```

### 2. Verify Configuration & Playwright MCP
```bash
# Run unit tests to verify configs and profile
python -m unittest discover tests

# Run the Playwright MCP test runner
python tests/test_playwright_mcp.py
```

### 3. Launch Dashboard (Shell)
```bash
streamlit run dashboard/app.py
```

### 4. Windows Server 2016 + IIS 10 Deployment
For hosting in enterprise Windows environments:
- Comprehensive step-by-step documentation: [`docs/DEPLOYMENT_WINDOWS_SERVER_2016_IIS.md`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/docs/DEPLOYMENT_WINDOWS_SERVER_2016_IIS.md)
- Production Streamlit configuration: [`.streamlit/config.toml`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/.streamlit/config.toml)
- IIS 10 Application Request Routing & WebSocket rules: [`deploy/iis/web.config`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/deploy/iis/web.config)
- Windows Service installer / uninstaller (NSSM): [`deploy/windows/service_install.ps1`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/deploy/windows/service_install.ps1) & [`deploy/windows/service_uninstall.ps1`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/deploy/windows/service_uninstall.ps1)
- Automated database backups: [`deploy/windows/backup_database.ps1`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/deploy/windows/backup_database.ps1)
- Production environment template: [`.env.production.example`](file:///Users/pranay/Documents/AI_Job_Application_Assistant/.env.production.example)

---

## 🗺️ Roadmap

- [x] **Phase 1:** Project initialization, directory structure, configs, candidate profile templates, Playwright MCP verification.
- [x] **Phase 2:** SQLite database & persistent application tracking (CRUD, deduplication, status tracking, transactions, backup/restore, CSV export).
- [x] **Phase 3:** Job matching and eligibility scoring engine (100-point multi-factor model, skill ontology, independent eligibility engine, transparent explanations).
- [x] **Phase 4:** Playwright MCP browser integration & safety fallbacks (accessibility tree inspection, TodoMVC interactive verification, data extraction schemas, anti-automation detection).
- [x] **Phase 5:** Modular job discovery adapters (LinkedIn, Internshala, Indeed, Naukri, Company Careers ATS feeds) with anti-automation defense handling, automated deduplication, real-time matching, and SQLite persistence.
- [x] **Phase 6:** Full Streamlit interactive dashboard with 8 dedicated views (Overview, Explore Jobs, Shortlisted Jobs, Application Tracker, Job Matching Analytics, Discovery Management, Candidate Profile, Settings), real-time SQLite metrics, interactive Plotly visualizations, skill gap analysis, state machine lifecycle management, human approval safeguards, live atomic database backup, and CSV export.
- [x] **Phase 7:** End-to-end Application Preparation Engine: zero-hallucination PDF/DOCX resume parsing, candidate profile synchronizer with immutable SQLite snapshots, resume-job alignment, personalized cover letter generator, screening question answer drafter with `NEEDS CANDIDATE INPUT` tagging, Playwright form pre-filling payload planner, and strict human-in-the-loop review packet & approval gate.
- [x] **Release Milestone: AI Job Application Assistant MVP Completion & Windows Server 2016 + IIS 10 Deployment Package**
  - Full end-to-end user workflow: registration, login, profile management, resume upload, JD ingestion, matching, document tailoring, packet review & approval gate, and manual application tracking.
  - Multi-tenant candidate isolation: Argon2id password hashing, SessionManager server-side session tokens, per-user resume/profile/packet sandboxing, zero profile leakage.
  - Production Windows deployment: NSSM Windows service wrapper, IIS 10 reverse proxy with WebSocket stream rewriting, online SQLite hot-backup scheduled tasks, and configurable directory overrides (`DATABASE_PATH`, `USER_STORAGE_BASE`, `EXPORTS_DIR`, `BACKUP_DIR`).


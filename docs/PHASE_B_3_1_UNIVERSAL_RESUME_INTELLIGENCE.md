# Architecture v2.1.1 Phase B.3.1: Universal Cross-Industry Resume Intelligence & Non-Blocking Discovery

## 1. Executive Summary

Phase B.3.1 resolves a critical product limitation in JobFlow AI: non-CS candidates (specifically multi-column ACCA, accounting, and finance candidates) encountered parsing hangs, blank profile fields, merged or dropped work experience records, omitted professional qualifications, irrelevant AI/ML search roles, duplicate job listings, and shared catalog match scores.

JobFlow AI is now **genuinely profession-independent**, providing layout-aware coordinate extraction, multi-record experience parsing, distinct ACCA Practical Experience Requirement (PER) management, cross-industry academic/credential recognition, non-blocking asynchronous job discovery, candidate-isolated matching, and native drag-and-drop file upload support.

---

## 2. Key Architecture & Engineering Enhancements

### 2.1 Layout-Aware Multi-Column PDF Extraction (`src/preparer/resume_parser.py`)
- **PyMuPDF Coordinate Block Analysis (`_order_page_blocks`):** Multi-column PDFs (such as modern Canva or ATS templates) share y-coordinates across horizontal bands. Linear extractors interleave credentials from the left column with employment roles from the right column. PyMuPDF block coordinate evaluation identifies visual columns ($x_0 < \text{split\_x}$ vs $x_0 \ge \text{split\_x}$), extracting top header bands first, followed by left column blocks (Education, Skills, Software, Languages), right column blocks (Work Experience), and bottom footer blocks.
- **PyPDF Linear Fallback:** When PyMuPDF is unavailable, the parser falls back gracefully to `pypdf.PdfReader` with robust exception handling.

### 2.2 Multi-Record Experience & Supervised ACCA PER Parsing (`src/preparer/resume_parser.py`)
- **Distinct Role Segmentation (`_extract_roles_from_text`):** Parses multi-position histories into individual `ExperienceEntry` objects, extracting employer, job title, start/end dates, duration, active status (`is_current`), and achievements.
- **Continuation & Header Suppression:** Filters out running headers, page numbers, and repeated section titles (e.g. `(Cont.)`, `Work Experience (Cont.)`, `Pranjali Agrawal — Experience & Credentials`), preventing header lines from collapsing roles.
- **Dedicated ACCA PER Pipeline (`_extract_acca_per`):** Practical Experience Requirement records for chartered accountancy are extracted into `ParsedResume.per_experience`, retaining mentor/supervisory context, performance objectives, and duration without conflating them with commercial employment.

### 2.3 Cross-Domain Education & Professional Qualifications
- **Academic Qualifications:** Comprehensive pattern matching for `BBA`, `B.Com`, `BMS`, `BCA`, `M.Com`, `HSC`, `SSC`, `Class 12`, and `Class 10` alongside standard engineering and medical degrees. Accurately extracts institution/board (e.g. `CBSE`), percentages (`93.8%`), and CGPA (`7.69`).
- **Statutory Credentials (`professional_qualifications`):** Extracts chartered accountancy and legal credentials (e.g. `ACCA Member`, `Association of Chartered Certified Accountants`) into both `certifications` and `professional_qualifications`.

### 2.4 Domain Skills, Software Tools & Languages
- **Domain Skills:** Captures non-IT technical competencies (e.g. `UK taxation`, `SA100 Self Assessment`, `Making Tax Digital`, `Accounts payable`, `Internal audit`, `Reconciliation`).
- **Enterprise Software Platforms (`tools_and_software`):** Detects industry software suites (`Digita`, `FYI`, `Xero`, `ApprovalMax`, `Coreplan`, `Microsoft Office Suite`, `Tally`, `QuickBooks`).
- **Languages:** Extracts business and spoken languages (`English`, `Hindi`, `Gujarati`).

### 2.5 Authoritative Profile Synchronization & Schema Consistency
- **Single-Pass Sync (`ProfileUpdater` & `routers/profile.py`):** Automatically maps parsed resume fields into the candidate's active profile in SQLite during upload without silent exception swallowing (`except Exception: pass` eliminated). If an error occurs, it is logged and reported via `sync_status = "FAILED"` and `sync_error = str(e)`.
- **Dual Schema Mapping:** Binds both canonical `personal` and legacy `personal_info` dictionaries, ensuring cross-version UI compatibility.
- **Frontend Field Alignment (`ProfilePage.tsx`):** Education inputs bind both `expected_graduation_year || graduation_year` and `current_cgpa || cgpa || percentage`, eliminating the blank field rendering issue.

### 2.6 Profession-Driven Career Role Inference & Query Generation
- **Career Role Inferencer (`CareerRoleInferencer`):** Expanded taxonomy with Finance, Tax, and Audit roles (`UK Tax Associate`, `Tax Compliance Associate`, `Accounts Associate`, `Accounts Payable Associate`, `Audit Associate`, `Internal Audit Associate`, `Financial Reporting Associate`). Derives target roles strictly from verifiable signals with zero AI/ML default bias.
- **Query Generator (`QueryGenerator`):** Removed default AI/ML keywords (`Machine Learning Intern`, `AI Intern`, `Python Developer`). Derives keyword queries from candidate target roles or returns empty matrix without fabricating tech keywords.

### 2.7 Non-Blocking Background Discovery & State Tracking (`routers/jobs.py`)
- **Asynchronous Execution:** `POST /api/jobs/discovery` accepts target roles and locations, creates a persistent record in the `discovery_runs` table, and initiates discovery on background worker threads without blocking HTTP responses.
- **Progress & Status Polling:** `GET /api/jobs/discovery/{run_id}` reports real-time execution state (`PENDING`, `RUNNING`, `COMPLETED`, `PARTIAL`, `FAILED`), newly discovered jobs count, and skipped duplicates.

### 2.8 Candidate-Isolated Matching & Job Deduplication
- **Candidate Isolation:** `GET /api/jobs` checks candidate-specific evaluations. Unassessed jobs return `is_evaluated: false`, `match_score: 0.0`, and `"Personalized evaluation pending"`, strictly blocking fallback to catalog-wide scores.
- **In-Memory Catalog Deduplication:** Deduplicates jobs across composite `(company_name, job_title, location)` and normalized URL, eliminating repeated entries (such as multiple Pledge India Foundation listings).

### 2.9 Frontend UI Modernization & File Dropzone Hardening
- **Universal Dropzone (`FileDropzone.tsx`):** Placed an absolute invisible native file input (`opacity-0 w-full h-full cursor-pointer z-10`) over the drag-and-drop container, solving Safari synthetic event suppression and enabling native click and drag-and-drop across all browsers.
- **Profile UI (`ProfilePage.tsx`):** Added dedicated cards for ACCA Practical Experience Requirement (PER), Professional Qualifications & Memberships, Software Tools & Platforms, and Languages.

---

## 3. Verification & Test Evidence

### 3.1 Targeted Test Suite (`tests/test_universal_resume_intelligence.py`)
- **10/10 tests passed (100%):**
  1. `test_two_column_coordinate_extraction`: Verifies PyMuPDF visual column ordering.
  2. `test_acca_education_extraction`: Verifies BBA Finance (CGPA 7.69) and HSC CBSE (93.8%).
  3. `test_acca_multi_record_experience`: Verifies 5 distinct roles parsed without collapse.
  4. `test_acca_per_supervised_experience`: Verifies ACCA PER record extracted.
  5. `test_acca_skills_software_languages`: Verifies domain skills, software tools, languages, and ACCA Member credential.
  6. `test_career_role_inference_acca_persona`: Verifies ACCA produces 0 AI/ML roles and 100% accounting/tax roles.
  7. `test_career_role_inference_cs_student`: Verifies CS student produces software/mobile/data roles.
  8. `test_query_generator_no_aiml_fallback`: Verifies query matrix excludes artificial AI/ML keywords.
  9. `test_profile_updater_build_profile_dict`: Verifies dictionary mapping and schema preservation.
  10. `test_discovery_run_state_lifecycle`: Verifies SQLite run creation, updates, and polling.

### 3.2 Full Repository Regression
- **91/91 tests passed (100%):**
  - Universal Resume Intelligence: 10/10 passed.
  - Profile & Matching Pipeline: 17/17 passed.
  - Phase 6.1 Hardening: 37/37 passed.
  - Tailored Resume Generator: 6/6 passed.
  - Universal Cover Letter Generator: 4/4 passed.
  - Universal Screening Questions: 5/5 passed.
  - Document Generation (PDF/DOCX): 6/6 passed.
  - Application Packet Integrity: 6/6 passed.
- **Linter & Static Analysis:**
  - `ruff check`: 0 errors.
  - `pyflakes`: 0 errors.
  - `npm run build`: built in 1.61s with 0 TypeScript/JSX errors.

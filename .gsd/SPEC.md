# SPEC.md — Real Employer Application Form Autofill & Human-Controlled Submission

Status: FINALIZED
Date: 2026-11-16
Version: 1.0.0
Branch: feat/modern-saas-frontend

---

## 1. Problem Statement
When a candidate prepares and approves an application in JobFlow AI, clicking the employer portal opens the application page, but the form remains empty. The candidate must manually re-type all their information and manually upload their resume.
Furthermore, previous iterations either attempted server-side headless browser filling (which ran invisible to the user), or faced cross-origin resource sharing (CORS) and third-party cookie restrictions when companion scripts executed on employer domains (e.g. `blueflamelabs.keka.com`).

## 2. Objective & User Experience
When a user opens an application from JobFlow:
1. JobFlow retrieves the validated canonical employer application URL.
2. The user clicks **Open Employer Application Form & Auto-Fill**.
3. The actual external application form opens in a separate browser tab while preserving JobFlow context.
4. The authenticated browser companion or extension connects with the new tab and backend using a short-lived, single-use cryptographically signed action ticket.
5. The verified resume binary (`.pdf` / `.docx`) is downloaded via the secure gateway and uploaded to the ATS file input (`#resume-upload`).
6. The companion observes the DOM with bounded polling until employer ATS resume parsing completes.
7. Remaining empty fields are populated using verified candidate facts from `UniversalFieldMapper` (name, phone, email, education, experience, skills, URLs, preferences).
8. Existing candidate edits and pre-populated ATS values are strictly preserved.
9. An in-page JobFlow Assistant card displays field-level results, highlighting populated fields in green and required manual inputs in amber.
10. **STRICT SAFETY INVARIANT:** Under NO circumstances will automation click "Submit Application", "Apply Now", or final declarations. The candidate personally inspects all values and clicks Apply.
11. An immutable `EXTERNAL_FORM_AUTOFILLED` audit event is recorded in `application_events` without modifying the application status to `SUBMITTED`.
12. The JobFlow dashboard displays live 9-stage operational progress and an interactive verified results table.

## 3. Security Requirements
1. **Zero Hallucination:** Sensitive candidate attributes (Gender, DOB, Salary, Notice Period, Legal Consent) are NEVER inferred from names or education.
2. **Cryptographic Action Tickets:** Issued per execution, HMAC-SHA256 signed, bound to `(user_id, application_id, execution_id, validated_domain, resume_file_hash, packet_hash)`, with 10-minute TTL and atomic replay prevention via `consumed_action_nonces`.
3. **No Wildcard CORS:** Dynamic CORS validation matching the specific `Origin` against the authorized `validated_domain` of the active plan.
4. **SSRF & Loopback Defense:** `URLSafetyValidator` blocks private IPv4/IPv6, carrier-grade NAT, cloud metadata (`169.254.169.254`), and loopback (`127.0.0.1`, `localhost`).
5. **Human Control Invariant:** Automation never clicks submit buttons or solves CAPTCHAs.

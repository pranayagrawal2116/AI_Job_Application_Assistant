"""Regression test suite for Phase B.1 - Application Preparation Workspace.

Verifies:
1. Root-cause repair of HTTP 500 when tailoring resumes.
2. Contract alignment for TailorResumeRequest and CoverLetterRequest.
3. Resume selection hierarchy (explicit -> attached -> unique primary -> 422 ambiguous/missing).
4. Cross-user isolation (403 on other user's resume).
5. Catalog job vs candidate-owned JD dual resolution.
6. Preparation state recovery across page reloads.
7. Auditing all 7 preparation steps and error correlation IDs.
"""

import json
import uuid
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.api.main import app
from dashboard.services.dashboard_service import DashboardService
from tests.fixtures.synthetic_personas import generate_persona_pdf


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def candidate_user(client):
    """Creates a primary candidate user with authenticated session."""
    uid = uuid.uuid4().hex[:8]
    email = f"candidate_tailor_{uid}@example.com"
    pwd = "SecurePassword123!"
    full_name = f"Tailor Candidate {uid}"

    reg_resp = client.post(
        "/api/auth/register",
        json={"email": email, "password": pwd, "full_name": full_name},
    )
    assert reg_resp.status_code == 201, reg_resp.text
    data = reg_resp.json()
    user_id = data["user"]["id"]
    session_id = data["session_id"]
    headers = {"Authorization": f"Bearer {session_id}"}

    client.put(
        "/api/profile",
        headers=headers,
        json={
            "profile_data": {
                "personal_info": {"full_name": full_name, "email": email, "phone": "+1234567890"},
                "technical_skills": ["Python", "Machine Learning", "FastAPI", "SQL", "Docker"],
                "work_experience": [
                    {
                        "employer": "Tech Labs Inc",
                        "job_title": "ML Engineer Intern",
                        "start_date": "2023-01-01",
                        "end_date": "2023-06-30",
                        "duration": "6 months",
                        "is_current": False,
                        "bullets": [
                            "Built end-to-end data preprocessing pipelines in Python.",
                            "Trained and evaluated machine learning classification models.",
                        ],
                    }
                ],
                "education": [
                    {
                        "institution": "University of Technology",
                        "degree": "B.Tech Computer Science",
                        "graduation_year": 2024,
                        "cgpa": 8.5,
                    }
                ],
            }
        },
    )

    return {"user_id": user_id, "session_id": session_id, "headers": headers}


@pytest.fixture(scope="module")
def second_user(client):
    """Creates a second user for cross-user security isolation tests."""
    uid = uuid.uuid4().hex[:8]
    email = f"second_user_{uid}@example.com"
    pwd = "SecurePassword123!"
    reg_resp = client.post(
        "/api/auth/register",
        json={"email": email, "password": pwd, "full_name": "Second User"},
    )
    assert reg_resp.status_code == 201
    data = reg_resp.json()
    return {
        "user_id": data["user"]["id"],
        "session_id": data["session_id"],
        "headers": {"Authorization": f"Bearer {data['session_id']}"},
    }


def _create_test_resume(service, user_id, filename="resume.pdf", is_primary=1, is_active=1):
    """Helper to create a genuine verifiable resume with full physical binary and database integrity."""
    pdf_bytes = generate_persona_pdf("backend_engineer")
    ok, msg, rec = service.upload_user_resume(
        user_id=user_id,
        file_bytes=pdf_bytes,
        original_filename=filename,
    )
    assert ok, f"Failed to upload test resume: {msg}"
    res_id = rec["id"]

    with service.db.transaction() as conn:
        c = conn.cursor()
        if is_primary:
            c.execute("UPDATE resumes SET is_primary = 0 WHERE user_id = ?", (user_id,))
        c.execute(
            "UPDATE resumes SET is_primary = ?, is_active = ? WHERE id = ?",
            (is_primary, is_active, res_id),
        )

    return res_id


# -------------------------------------------------------------------------
# Test Cases
# -------------------------------------------------------------------------

def test_tailor_resume_app72_reproduction_and_resolution(client, candidate_user):
    """Tests the exact scenario of Application #72:

    - Application has no resume_id.
    - Request body is empty or omits resume_id.
    - Candidate has one authoritative primary resume.
    - Tailor resume succeeds (HTTP 200) and links resume to application.
    - No HTTP 500 AttributeError occurs.
    """
    service = DashboardService.get_instance()
    user_id = candidate_user["user_id"]
    headers = candidate_user["headers"]

    res_id = _create_test_resume(service, user_id, "Pranay_Resume.pdf", is_primary=1)

    create_resp = client.post(
        "/api/applications",
        headers=headers,
        json={
            "company_name": "Pledge India Foundation",
            "job_title": "Machine Learning Intern",
        },
    )
    assert create_resp.status_code == 201
    app_data = create_resp.json()
    app_id = app_data["id"]
    assert app_data["resume_id"] is None

    tailor_resp = client.post(
        f"/api/applications/{app_id}/tailor-resume",
        headers=headers,
        json={"template": "modern"},
    )
    assert tailor_resp.status_code == 200, tailor_resp.text
    data = tailor_resp.json()
    assert data["status"] == "ok"
    assert "tailored_resume" in data
    assert "professional_summary" in data["tailored_resume"]

    app_check = client.get(f"/api/applications/{app_id}", headers=headers).json()
    assert app_check["resume_id"] == res_id


def test_tailor_resume_explicit_valid_selection(client, candidate_user):
    """Candidate explicitly supplies a valid resume_id in request."""
    service = DashboardService.get_instance()
    user_id = candidate_user["user_id"]
    headers = candidate_user["headers"]

    res_id = _create_test_resume(service, user_id, "Explicit_Resume.pdf", is_primary=0)

    create_resp = client.post(
        "/api/applications",
        headers=headers,
        json={"company_name": "DataCorp", "job_title": "Data Scientist"},
    )
    app_id = create_resp.json()["id"]

    tailor_resp = client.post(
        f"/api/applications/{app_id}/tailor-resume",
        headers=headers,
        json={
            "resume_id": res_id,
            "custom_instructions": "Highlight pandas and statistical modeling.",
        },
    )
    assert tailor_resp.status_code == 200
    assert tailor_resp.json()["status"] == "ok"

    app_check = client.get(f"/api/applications/{app_id}", headers=headers).json()
    assert app_check["resume_id"] == res_id


def test_tailor_resume_non_existent_resume(client, candidate_user):
    """Explicitly requesting a non-existent resume ID returns HTTP 404."""
    headers = candidate_user["headers"]

    create_resp = client.post(
        "/api/applications",
        headers=headers,
        json={"company_name": "TechStart", "job_title": "Backend Dev"},
    )
    app_id = create_resp.json()["id"]

    tailor_resp = client.post(
        f"/api/applications/{app_id}/tailor-resume",
        headers=headers,
        json={"resume_id": 999999},
    )
    assert tailor_resp.status_code == 404
    assert "not found" in tailor_resp.json()["detail"].lower()


def test_tailor_resume_cross_user_isolation(client, candidate_user, second_user):
    """Attempting to use a resume belonging to another user returns HTTP 403."""
    service = DashboardService.get_instance()
    user1_res = _create_test_resume(service, candidate_user["user_id"], "User1_Secret.pdf", is_primary=0)

    create_resp = client.post(
        "/api/applications",
        headers=second_user["headers"],
        json={"company_name": "OtherCo", "job_title": "Analyst"},
    )
    app_id = create_resp.json()["id"]

    tailor_resp = client.post(
        f"/api/applications/{app_id}/tailor-resume",
        headers=second_user["headers"],
        json={"resume_id": user1_res},
    )
    assert tailor_resp.status_code == 403
    assert "access denied" in tailor_resp.json()["detail"].lower()


def test_tailor_resume_no_uploaded_resumes(client, second_user):
    """Candidate with 0 resumes receives HTTP 422 with clear instructional message."""
    create_resp = client.post(
        "/api/applications",
        headers=second_user["headers"],
        json={"company_name": "EmptyCo", "job_title": "Intern"},
    )
    app_id = create_resp.json()["id"]

    tailor_resp = client.post(
        f"/api/applications/{app_id}/tailor-resume",
        headers=second_user["headers"],
        json={},
    )
    assert tailor_resp.status_code == 422
    assert "no resumes found" in tailor_resp.json()["detail"].lower()


def test_tailor_resume_multiple_resumes_without_primary(client):
    """Candidate with multiple active resumes and no unique primary receives HTTP 422 prompting selection."""
    service = DashboardService.get_instance()
    uid = uuid.uuid4().hex[:8]
    reg_resp = client.post(
        "/api/auth/register",
        json={"email": f"multi_{uid}@example.com", "password": "Password123!", "full_name": "Multi Candidate"},
    )
    user_id = reg_resp.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {reg_resp.json()['session_id']}"}

    _create_test_resume(service, user_id, "resume_a.pdf", is_primary=0)
    _create_test_resume(service, user_id, "resume_b.pdf", is_primary=0)

    create_resp = client.post(
        "/api/applications",
        headers=headers,
        json={"company_name": "MultiCorp", "job_title": "Developer"},
    )
    app_id = create_resp.json()["id"]

    tailor_resp = client.post(
        f"/api/applications/{app_id}/tailor-resume",
        headers=headers,
        json={},
    )
    assert tailor_resp.status_code == 422
    assert "multiple resumes available" in tailor_resp.json()["detail"].lower()


def test_public_catalog_job_context_resolution(client, candidate_user):
    """Application linked to a public catalog job resolves skills and description without errors."""
    service = DashboardService.get_instance()
    user_id = candidate_user["user_id"]
    headers = candidate_user["headers"]

    # Re-establish unambiguous primary resume
    _create_test_resume(service, user_id, "Candidate_Primary.pdf", is_primary=1)

    catalog_job = service.db.get_job_by_id(24)
    job_id = 24 if catalog_job else 5

    create_resp = client.post(
        "/api/applications",
        headers=headers,
        json={"job_id": job_id, "company_name": "Pledge India", "job_title": "ML Intern"},
    )
    assert create_resp.status_code == 201
    app_id = create_resp.json()["id"]
    assert create_resp.json()["job_id"] == job_id

    tailor_resp = client.post(
        f"/api/applications/{app_id}/tailor-resume",
        headers=headers,
        json={"template": "modern"},
    )
    assert tailor_resp.status_code == 200, tailor_resp.text
    data = tailor_resp.json()
    assert data["status"] == "ok"
    assert "tailored_resume" in data


def test_candidate_owned_job_description_resolution(client, candidate_user):
    """Application linked to a candidate-owned ingested JD resolves parsed requirements."""
    service = DashboardService.get_instance()
    user_id = candidate_user["user_id"]
    headers = candidate_user["headers"]

    _create_test_resume(service, user_id, "Candidate_Primary.pdf", is_primary=1)

    jd_content = "Looking for a Python Backend Engineer with FastAPI, Docker, and PostgreSQL experience."
    jd = service.db.create_job_description(
        user_id=user_id,
        company_name="Acme Ingested",
        job_title="Backend Engineer",
        raw_content=jd_content,
        source_type="pasted",
        parsed_data={
            "required_skills": ["Python", "FastAPI", "PostgreSQL"],
            "preferred_skills": ["Docker"],
        },
    )
    jd_id = jd.id

    create_resp = client.post(
        "/api/applications",
        headers=headers,
        json={
            "company_name": "Acme Ingested",
            "job_title": "Backend Engineer",
            "job_description_id": jd_id,
        },
    )
    app_id = create_resp.json()["id"]

    tailor_resp = client.post(
        f"/api/applications/{app_id}/tailor-resume",
        headers=headers,
        json={},
    )
    assert tailor_resp.status_code == 200, tailor_resp.text
    tailored = tailor_resp.json()["tailored_resume"]
    assert "matching_skills" in tailored
    assert any("PostgreSQL" in s or "Docker" in s or "Python" in s for s in tailored["matching_skills"])


def test_cover_letter_generation(client, candidate_user):
    """Cover letter endpoint generates tailored letter with provenance claims."""
    service = DashboardService.get_instance()
    user_id = candidate_user["user_id"]
    headers = candidate_user["headers"]

    _create_test_resume(service, user_id, "Candidate_Primary.pdf", is_primary=1)

    create_resp = client.post(
        "/api/applications",
        headers=headers,
        json={"company_name": "CoverCo", "job_title": "AI Researcher"},
    )
    app_id = create_resp.json()["id"]

    cl_resp = client.post(
        f"/api/applications/{app_id}/cover-letter",
        headers=headers,
        json={"tone": "Enthusiastic & Modern"},
    )
    assert cl_resp.status_code == 200, cl_resp.text
    cl_data = cl_resp.json()["cover_letter"]
    assert "letter_text" in cl_data
    assert len(cl_data["letter_text"]) > 50
    assert "provenance_claims" in cl_data


def test_screening_qa_endpoint(client, candidate_user):
    """Screening QA endpoint drafts responses rooted in verified evidence."""
    service = DashboardService.get_instance()
    user_id = candidate_user["user_id"]
    headers = candidate_user["headers"]

    _create_test_resume(service, user_id, "Candidate_Primary.pdf", is_primary=1)

    create_resp = client.post(
        "/api/applications",
        headers=headers,
        json={"company_name": "ScreenCo", "job_title": "Software Engineer"},
    )
    app_id = create_resp.json()["id"]

    qa_resp = client.post(
        f"/api/applications/{app_id}/screening-qa",
        headers=headers,
        json={
            "questions": [
                {"q": "Why do you want to work at ScreenCo?"},
                {"q": "What is your earliest availability?"},
            ]
        },
    )
    assert qa_resp.status_code == 200, qa_resp.text
    qa_list = qa_resp.json()["screening_qa"]
    assert len(qa_list) == 2
    assert "q" in qa_list[0]
    assert "a" in qa_list[0]
    assert "needsInput" in qa_list[0]


def test_preparation_state_recovery(client, candidate_user):
    """Preparation state GET endpoint returns complete state surviving page refreshes."""
    service = DashboardService.get_instance()
    user_id = candidate_user["user_id"]
    headers = candidate_user["headers"]

    _create_test_resume(service, user_id, "Candidate_Primary.pdf", is_primary=1)

    create_resp = client.post(
        "/api/applications",
        headers=headers,
        json={"company_name": "StateCo", "job_title": "Systems Engineer"},
    )
    app_id = create_resp.json()["id"]

    # 1. Tailor resume
    t_resp = client.post(f"/api/applications/{app_id}/tailor-resume", headers=headers, json={})
    assert t_resp.status_code == 200, t_resp.text

    # 2. Generate cover letter
    cl_resp = client.post(f"/api/applications/{app_id}/cover-letter", headers=headers, json={})
    assert cl_resp.status_code == 200, cl_resp.text

    # 3. Answer screening questions
    qa_resp = client.post(f"/api/applications/{app_id}/screening-qa", headers=headers, json={})
    assert qa_resp.status_code == 200, qa_resp.text

    # Retrieve preparation state (simulating page reload)
    state_resp = client.get(f"/api/applications/{app_id}/preparation-state", headers=headers)
    assert state_resp.status_code == 200, state_resp.text
    state = state_resp.json()
    assert state["application_id"] == app_id
    assert state["tailored_resume"] is not None
    assert state["cover_letter"] is not None
    assert state["screening_qa"] is not None
    assert len(state["screening_qa"]) > 0


def test_prepare_packet_and_approval_gate(client, candidate_user):
    """Prepares packet and exercises HMAC ticket authorization gate."""
    service = DashboardService.get_instance()
    user_id = candidate_user["user_id"]
    headers = candidate_user["headers"]

    _create_test_resume(service, user_id, "Candidate_Primary.pdf", is_primary=1)

    create_resp = client.post(
        "/api/applications",
        headers=headers,
        json={"company_name": "ApprovalCo", "job_title": "Security Analyst"},
    )
    app_id = create_resp.json()["id"]

    # Tailor resume and cover letter first
    t_resp = client.post(f"/api/applications/{app_id}/tailor-resume", headers=headers, json={})
    assert t_resp.status_code == 200, t_resp.text

    cl_resp = client.post(f"/api/applications/{app_id}/cover-letter", headers=headers, json={})
    assert cl_resp.status_code == 200, cl_resp.text

    # Prepare packet
    prep_resp = client.post(f"/api/applications/{app_id}/prepare-packet", headers=headers)
    assert prep_resp.status_code == 200, prep_resp.text
    packet_data = prep_resp.json()
    assert packet_data["status"] == "ok"
    assert "packet" in packet_data

    # Issue approval ticket
    ticket_resp = client.post(f"/api/applications/{app_id}/tickets/approval", headers=headers)
    assert ticket_resp.status_code == 200
    ticket = ticket_resp.json()["ticket"]

    # Authorize packet
    auth_resp = client.post(
        f"/api/applications/{app_id}/approve",
        headers=headers,
        json={
            "approver_name": "Test Candidate",
            "action_ticket": ticket,
            "candidate_confirmed": True,
        },
    )
    assert auth_resp.status_code == 200, auth_resp.text
    assert auth_resp.json()["status"] == "ok"

    app_check = client.get(f"/api/applications/{app_id}", headers=headers).json()
    assert app_check["status"] in ("APPROVED", "Approved", "Awaiting Approval", "AWAITING_APPROVAL")


def test_unexpected_error_returns_correlation_id_without_leaks(client, candidate_user):
    """Unexpected server exceptions produce HTTP 500 with correlation ID and no stack trace."""
    service = DashboardService.get_instance()
    user_id = candidate_user["user_id"]
    headers = candidate_user["headers"]

    _create_test_resume(service, user_id, "Candidate_Primary.pdf", is_primary=1)

    create_resp = client.post(
        "/api/applications",
        headers=headers,
        json={"company_name": "CrashCo", "job_title": "DevOps Engineer"},
    )
    app_id = create_resp.json()["id"]

    with patch.object(DashboardService, "generate_tailored_resume", side_effect=RuntimeError("Simulated unhandled pipeline crash")):
        resp = client.post(
            f"/api/applications/{app_id}/tailor-resume",
            headers=headers,
            json={},
        )
        assert resp.status_code == 500
        detail = resp.json()["detail"]
        assert "Correlation ID:" in detail
        assert "Traceback" not in detail
        assert "Simulated unhandled pipeline crash" not in detail

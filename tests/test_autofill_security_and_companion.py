"""Unit and Integration Tests for External Form Autofill Security,
Dynamic CORS, Single-Use Action Tickets, and Companion Lifecycle.
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from backend.api.main import app
from dashboard.services.dashboard_service import DashboardService
from src.preparer.form_filling_broker import ApplicationFormFillingBroker
from tests.fixtures.synthetic_personas import generate_persona_pdf


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def candidate_user(client):
    """Creates a candidate user with authenticated session, resume, and application."""
    uid = uuid.uuid4().hex[:8]
    email = f"candidate_test_{uid}@example.com"
    pwd = "SecurePassword123!"
    full_name = f"Samantha Reed {uid}"

    reg_resp = client.post(
        "/api/auth/register",
        json={"email": email, "password": pwd, "full_name": full_name},
    )
    assert reg_resp.status_code == 201, reg_resp.text
    data = reg_resp.json()
    user_id = data["user"]["id"]
    session_id = data["session_id"]
    headers = {"Authorization": f"Bearer {session_id}"}

    service = DashboardService.get_instance()
    db = service.db

    # Upload test resume using structurally valid PDF
    sample_pdf = generate_persona_pdf("backend_engineer")
    upload_resp = client.post(
        "/api/profile/resumes/upload",
        files={"file": ("candidate_resume.pdf", sample_pdf, "application/pdf")},
        data={"is_primary": "true"},
        headers=headers,
    )
    assert upload_resp.status_code == 201, upload_resp.text
    resume_id = upload_resp.json()["id"]

    # Insert a test application in APPROVED state
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO applications (
                user_id, resume_id, company_name, job_title,
                status, external_application_url, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            """,
            (
                user_id,
                resume_id,
                "Blueflame Labs",
                "Project Manager",
                "APPROVED",
                "https://blueflamelabs.keka.com/careers/applyjob/12345",
            ),
        )
        app_id = cursor.lastrowid
        conn.commit()

    return {
        "user_id": user_id,
        "session_id": session_id,
        "headers": headers,
        "resume_id": resume_id,
        "app_id": app_id,
    }


def test_autofill_plan_generation_and_dynamic_cors(client, candidate_user):
    """Tests plan generation, dynamic CORS validation, and domain registration."""
    headers = candidate_user["headers"]
    app_id = candidate_user["app_id"]

    # 1. Generate autofill plan
    plan_resp = client.post(
        f"/api/applications/{app_id}/autofill/plan",
        json={"target_url": "https://blueflamelabs.keka.com/careers/applyjob/12345"},
        headers=headers,
    )
    assert plan_resp.status_code == 200, plan_resp.text
    plan = plan_resp.json()

    assert plan["application_id"] == app_id
    assert plan["ats_provider"].upper() == "KEKA"
    assert plan["validated_domain"] == "blueflamelabs.keka.com"
    assert "action_ticket" in plan
    assert "execution_id" in plan
    ticket = plan["action_ticket"]
    execution_id = plan["execution_id"]

    # 2. Test dynamic CORS: Allowed origin (active employer domain)
    cors_resp = client.options(
        f"/api/applications/{app_id}/autofill/status?execution_id={execution_id}",
        headers={"Origin": "https://blueflamelabs.keka.com"},
    )
    assert cors_resp.status_code == 200
    assert cors_resp.headers.get("access-control-allow-origin") == "https://blueflamelabs.keka.com"
    assert cors_resp.headers.get("access-control-allow-origin") != "*"

    # 3. Test dynamic CORS: Extension origin
    ext_resp = client.options(
        f"/api/applications/{app_id}/autofill/status?execution_id={execution_id}",
        headers={"Origin": "chrome-extension://abcdefghijklmnop"},
    )
    assert ext_resp.status_code == 200
    assert ext_resp.headers.get("access-control-allow-origin") == "chrome-extension://abcdefghijklmnop"

    # 4. Test dynamic CORS: Unauthorized third-party origin rejected from CORS headers
    bad_resp = client.options(
        f"/api/applications/{app_id}/autofill/status?execution_id={execution_id}",
        headers={"Origin": "https://malicious-tracker.evil.com"},
    )
    assert bad_resp.headers.get("access-control-allow-origin") is None


def test_single_use_action_ticket_and_replay_prevention(client, candidate_user):
    """Verifies that an action ticket can be consumed once and rejected on replay."""
    headers = candidate_user["headers"]
    app_id = candidate_user["app_id"]

    # Generate fresh plan with new ticket
    plan_resp = client.post(
        f"/api/applications/{app_id}/autofill/plan",
        json={"target_url": "https://blueflamelabs.keka.com/careers/applyjob/12345"},
        headers=headers,
    )
    assert plan_resp.status_code == 200
    ticket = plan_resp.json()["action_ticket"]

    # First fetch: should succeed and return binary
    fetch_resp = client.get(
        f"/api/applications/{app_id}/autofill/resume-binary?ticket={ticket}",
    )
    assert fetch_resp.status_code == 200
    assert fetch_resp.headers["content-type"] == "application/pdf"
    assert b"%PDF" in fetch_resp.content

    # Second fetch with identical ticket: MUST FAIL (replay prevention)
    replay_resp = client.get(
        f"/api/applications/{app_id}/autofill/resume-binary?ticket={ticket}",
    )
    assert replay_resp.status_code == 401
    assert "already been used" in replay_resp.json()["detail"].lower() or "replay" in replay_resp.json()["detail"].lower()


def test_companion_complete_and_strict_human_control(client, candidate_user):
    """Verifies complete execution report submission and preserves application status."""
    headers = candidate_user["headers"]
    app_id = candidate_user["app_id"]

    # 1. Create plan
    plan_resp = client.post(
        f"/api/applications/{app_id}/autofill/plan",
        json={"target_url": "https://blueflamelabs.keka.com/careers/applyjob/12345"},
        headers=headers,
    )
    plan = plan_resp.json()
    ticket = plan["action_ticket"]
    execution_id = plan["execution_id"]

    # 2. Check live status polling
    status_resp = client.get(
        f"/api/applications/{app_id}/autofill/status?execution_id={execution_id}",
        headers=headers,
    )
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] in ["READY", "PENDING", "RUNNING"]

    # 3. Companion posts completion report using action ticket Authorization header (no cookies required)
    complete_report = {
        "action_ticket": ticket,
        "execution_id": execution_id,
        "ats_provider": "keka",
        "target_url": "https://blueflamelabs.keka.com/careers/applyjob/12345",
        "resume_uploaded": True,
        "fields_populated": 6,
        "fields_preserved": 2,
        "manual_review_fields": 1,
        "field_results": [
            {"target_name": "Full Name", "matched_fact": "full_name", "value_written": "Jane Doe", "action": "POPULATED"},
            {"target_name": "Email", "matched_fact": "email", "value_written": "jane@example.com", "action": "POPULATED"},
        ],
    }

    comp_resp = client.post(
        f"/api/applications/{app_id}/autofill/complete",
        json=complete_report,
        headers={"Authorization": f"Bearer {ticket}"},
    )
    assert comp_resp.status_code == 200
    res_data = comp_resp.json()
    assert res_data["success"] is True

    # 4. Status should now be COMPLETED
    status_after = client.get(
        f"/api/applications/{app_id}/autofill/status?execution_id={execution_id}",
        headers=headers,
    )
    assert status_after.status_code == 200
    assert status_after.json()["status"] == "COMPLETED"

    # 5. STRICT HUMAN CONTROL: Verify application status was NOT changed to SUBMITTED or APPLIED!
    app_check = client.get(f"/api/applications/{app_id}", headers=headers)
    assert app_check.status_code == 200
    assert app_check.json()["status"] == "APPROVED"
    assert app_check.json()["status"] != "APPLIED"
    assert app_check.json()["status"] != "SUBMITTED"

    # 6. Audit Logging: Verify EXTERNAL_FORM_AUTOFILLED event is recorded
    service = DashboardService.get_instance()
    with service.db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT event_type, event_payload_json FROM application_events WHERE application_id = ? AND event_type = 'EXTERNAL_FORM_AUTOFILLED'",
            (app_id,),
        )
        events = cursor.fetchall()
        assert len(events) >= 1
        ev = events[0]
        assert ev["event_type"] == "EXTERNAL_FORM_AUTOFILLED"


def test_companion_script_injection(client, candidate_user):
    """Verifies that the companion JavaScript is served correctly with secure configs."""
    headers = candidate_user["headers"]
    app_id = candidate_user["app_id"]

    # Fetch companion script
    resp = client.get(f"/api/applications/{app_id}/autofill/companion.js?ticket=test_ticket&execution_id=exec_123")
    assert resp.status_code == 200
    assert "javascript" in resp.headers["content-type"]
    content = resp.text
    assert "window.JOBFLOW_CONFIG" in content
    assert f"appId: {app_id}" in content
    assert "test_ticket" in content
    assert "exec_123" in content

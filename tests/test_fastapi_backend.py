"""Integration tests for FastAPI REST API endpoints."""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from backend.api.main import app
from src.database.db_manager import DatabaseManager
from dashboard.services.dashboard_service import DashboardService


@pytest.fixture(scope="module")
def test_client():
    client = TestClient(app)
    return client


def test_api_health(test_client):
    response = test_client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "2.1.1"


def test_spa_serving(test_client):
    # Test that frontend dist index.html is served
    resp = test_client.get("/")
    assert resp.status_code == 200
    assert "JobFlow" in resp.text
    assert "root" in resp.text


def test_auth_and_session_lifecycle(test_client):
    # Unique email for registration
    import uuid
    uid = uuid.uuid4().hex[:8]
    email = f"candidate_{uid}@example.com"
    password = "SecurePassword123!"
    full_name = f"Candidate {uid}"

    # 1. Register
    reg_resp = test_client.post(
        "/api/auth/register",
        json={"email": email, "password": password, "full_name": full_name},
    )
    assert reg_resp.status_code == 201, reg_resp.text
    reg_data = reg_resp.json()
    assert reg_data["user"]["email"] == email
    assert "session_id" in reg_data

    session_id = reg_data["session_id"]
    headers = {"Authorization": f"Bearer {session_id}"}

    # 2. Get Me
    me_resp = test_client.get("/api/auth/me", headers=headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == email

    # 3. Dashboard Summary
    dash_resp = test_client.get("/api/dashboard/summary", headers=headers)
    assert dash_resp.status_code == 200
    dash_data = dash_resp.json()
    assert "profile_completeness" in dash_data
    assert "total_opportunities" in dash_data
    assert "recommended_action" in dash_data

    # 4. Profile GET & PUT
    prof_resp = test_client.get("/api/profile", headers=headers)
    assert prof_resp.status_code == 200

    update_resp = test_client.put(
        "/api/profile",
        headers=headers,
        json={
            "profile_data": {
                "personal_info": {"full_name": full_name, "email": email, "phone": "+1234567890"},
                "technical_skills": ["Python", "FastAPI", "React", "TypeScript"],
            }
        },
    )
    assert update_resp.status_code == 200
    assert "Python" in update_resp.json()["profile_data"]["technical_skills"]

    # 5. Jobs list
    jobs_resp = test_client.get("/api/jobs", headers=headers)
    assert jobs_resp.status_code == 200
    jobs = jobs_resp.json()
    assert isinstance(jobs, list)

    # 6. Applications Workspace
    app_create_resp = test_client.post(
        "/api/applications",
        headers=headers,
        json={"company_name": "Acme Robotics", "job_title": "AI Engineer"},
    )
    assert app_create_resp.status_code == 201
    created_app = app_create_resp.json()
    app_id = created_app["id"]
    assert created_app["status"] in ("DRAFT", "Draft")

    # List applications
    apps_list_resp = test_client.get("/api/applications", headers=headers)
    assert apps_list_resp.status_code == 200
    assert any(a["id"] == app_id for a in apps_list_resp.json())

    # Get single application
    app_detail_resp = test_client.get(f"/api/applications/{app_id}", headers=headers)
    assert app_detail_resp.status_code == 200
    assert app_detail_resp.json()["company_name"] == "Acme Robotics"

    # Status transition to PREPARING
    trans_resp = test_client.patch(
        f"/api/applications/{app_id}/status",
        headers=headers,
        json={"status": "PREPARING"},
    )
    assert trans_resp.status_code == 200
    assert trans_resp.json()["status"] in ("PREPARING", "Preparing")

    # Timeline
    timeline_resp = test_client.get(f"/api/applications/{app_id}/timeline", headers=headers)
    assert timeline_resp.status_code == 200
    assert "timeline" in timeline_resp.json()

    # Follow-up scheduling
    fu_resp = test_client.post(
        f"/api/applications/{app_id}/followups",
        headers=headers,
        json={
            "follow_up_type": "Check Application Status",
            "scheduled_date": "2026-12-01",
            "notes": "Follow up with HR recruiter",
        },
    )
    assert fu_resp.status_code == 201
    assert fu_resp.json()["follow_up_type"] == "STATUS_INQUIRY"

    list_fu_resp = test_client.get(f"/api/applications/{app_id}/followups", headers=headers)
    assert list_fu_resp.status_code == 200
    assert len(list_fu_resp.json()) >= 1

    # Matching profiles
    profiles_resp = test_client.get("/api/matching/profiles", headers=headers)
    assert profiles_resp.status_code == 200
    assert "profiles" in profiles_resp.json()

    # Settings backup and export
    backup_resp = test_client.post("/api/settings/backup", headers=headers)
    assert backup_resp.status_code == 200
    assert "backup_path" in backup_resp.json()

    export_resp = test_client.get("/api/settings/export/csv", headers=headers)
    assert export_resp.status_code == 200
    assert export_resp.headers["content-type"].startswith("text/csv")

    # 7. Logout
    logout_resp = test_client.post("/api/auth/logout", headers=headers)
    assert logout_resp.status_code == 200

    # Verify session revoked
    me_revoked_resp = test_client.get("/api/auth/me", headers=headers)
    assert me_revoked_resp.status_code == 401


def test_cookie_auth_and_csrf_protection(test_client):
    import uuid
    uid = uuid.uuid4().hex[:8]
    email = f"csrf_candidate_{uid}@example.com"
    password = "SecurePassword123!"
    full_name = f"CSRF Candidate {uid}"

    # 1. Register with client to obtain cookies
    reg_resp = test_client.post(
        "/api/auth/register",
        json={"email": email, "password": password, "full_name": full_name},
    )
    assert reg_resp.status_code == 201
    assert "session_id" in test_client.cookies
    assert "csrf_token" in test_client.cookies
    csrf_token = test_client.cookies["csrf_token"]

    # 2. Mutating request WITHOUT X-CSRF-Token header should fail with 403 Forbidden
    fail_resp = test_client.put(
        "/api/profile",
        json={"profile_data": {"personal_info": {"full_name": full_name, "email": email}}},
    )
    assert fail_resp.status_code == 403
    assert "CSRF verification failed" in fail_resp.json()["detail"]

    # 3. Mutating request with incorrect X-CSRF-Token header should fail with 403
    fail_resp2 = test_client.put(
        "/api/profile",
        headers={"X-CSRF-Token": "invalid_csrf_token"},
        json={"profile_data": {"personal_info": {"full_name": full_name, "email": email}}},
    )
    assert fail_resp2.status_code == 403

    # 4. Mutating request WITH matching X-CSRF-Token header should succeed
    success_resp = test_client.put(
        "/api/profile",
        headers={"X-CSRF-Token": csrf_token},
        json={"profile_data": {"personal_info": {"full_name": full_name, "email": email}, "technical_skills": ["FastAPI", "React"]}},
    )
    assert success_resp.status_code == 200

    # 5. Non-mutating GET request should succeed without CSRF token
    get_resp = test_client.get("/api/auth/me")
    assert get_resp.status_code == 200
    assert get_resp.json()["email"] == email

    # 6. Logout with CSRF token
    logout_resp = test_client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout_resp.status_code == 200

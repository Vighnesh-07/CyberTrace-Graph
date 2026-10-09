import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch, AsyncMock
from dashboard.api.routers.soar import router
from dashboard.api.core.security import get_current_user
import asyncio

# Create test app
test_app = FastAPI()

# Override auth dependency
async def mock_get_current_user():
    return "test_admin"

test_app.include_router(router, prefix="/api/soar")
test_app.dependency_overrides[get_current_user] = mock_get_current_user

# Setup mock neo4j on app state
mock_neo4j = MagicMock()
mock_neo4j._run_query = MagicMock(return_value=[])
mock_neo4j.update_alert_status = MagicMock(return_value=None)

@test_app.on_event("startup")
async def setup_test_state():
    test_app.state.neo4j = mock_neo4j

# We use TestClient which triggers startup events if used as a context manager, 
# but FastAPI TestClient might not trigger startup events just by initialization in older versions.
# We explicitly set state to be safe.
test_app.state.neo4j = mock_neo4j

client = TestClient(test_app)

@pytest.fixture(autouse=True)
def reset_mocks():
    mock_neo4j.reset_mock()
    mock_neo4j._run_query.return_value = []
    yield

@pytest.fixture(autouse=True)
def patch_sleep():
    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        yield mock_sleep

class TestSOARBlockIP:
    def test_block_ip_returns_success(self):
        response = client.post(
            "/api/soar/block-ip",
            json={"ip": "192.168.1.100", "reason": "Malicious activity"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "COMPLETED"
        assert data["action_type"] == "BLOCK_IP"
        assert data["target"] == "192.168.1.100"

    def test_block_ip_requires_authentication(self):
        # Temporarily remove dependency override to test auth requirement
        test_app.dependency_overrides.pop(get_current_user)
        try:
            response = client.post(
                "/api/soar/block-ip",
                json={"ip": "192.168.1.100", "reason": "Malicious activity"}
            )
            assert response.status_code == 401
        finally:
            test_app.dependency_overrides[get_current_user] = mock_get_current_user

    def test_block_ip_writes_audit_log(self):
        response = client.post(
            "/api/soar/block-ip",
            json={"ip": "10.0.0.5", "alert_id": "ALT-123", "reason": "Testing"}
        )
        assert response.status_code == 200
        # Check that neo4j._run_query was called
        assert mock_neo4j._run_query.called

    def test_block_ip_response_structure(self):
        response = client.post(
            "/api/soar/block-ip",
            json={"ip": "1.1.1.1", "reason": "Bad IP"}
        )
        assert response.status_code == 200
        data = response.json()
        expected_keys = {"action_id", "action_type", "target", "status", "webhook_result", "executed_by"}
        assert expected_keys.issubset(set(data.keys()))
        assert data["executed_by"] == "test_admin"

class TestSOARIsolateHost:
    def test_isolate_host_returns_success(self):
        response = client.post(
            "/api/soar/isolate-host",
            json={"hostname": "workstation-01", "reason": "Ransomware"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "COMPLETED"
        assert data["action_type"] == "ISOLATE_HOST"
        assert data["target"] == "workstation-01"

    def test_isolate_host_response_structure(self):
        response = client.post(
            "/api/soar/isolate-host",
            json={"hostname": "server-02", "reason": "Lateral movement"}
        )
        assert response.status_code == 200
        data = response.json()
        expected_keys = {"action_id", "action_type", "target", "status", "webhook_result", "executed_by"}
        assert expected_keys.issubset(set(data.keys()))
        assert data["executed_by"] == "test_admin"

class TestSOARKillProcess:
    def test_kill_process_returns_success(self):
        response = client.post(
            "/api/soar/kill-process",
            json={"hostname": "workstation-01", "process_name": "mimikatz.exe", "reason": "Credential dumping"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "COMPLETED"
        assert data["action_type"] == "KILL_PROCESS"
        assert data["target"] == "workstation-01:mimikatz.exe"

    def test_kill_process_response_structure(self):
        response = client.post(
            "/api/soar/kill-process",
            json={"hostname": "server-01", "process_name": "nc.exe"}
        )
        assert response.status_code == 200
        data = response.json()
        expected_keys = {"action_id", "action_type", "target", "status", "webhook_result", "executed_by"}
        assert expected_keys.issubset(set(data.keys()))
        assert data["executed_by"] == "test_admin"

class TestSOARActions:
    def test_get_actions_returns_list(self):
        mock_neo4j._run_query.return_value = [{"ra": {"action_id": "ACT-123", "action_type": "block_ip"}}]
        response = client.get("/api/soar/actions")
        assert response.status_code == 200
        data = response.json()
        assert "actions" in data
        assert "total" in data

    def test_get_actions_with_alert_id_filter(self):
        mock_neo4j._run_query.return_value = []
        response = client.get("/api/soar/actions?alert_id=ALT-123")
        assert response.status_code == 200
        assert mock_neo4j._run_query.called

class TestSOARAuditLog:
    def test_get_audit_log_returns_entries(self):
        mock_neo4j._run_query.return_value = [{"al": {"log_id": "LOG-1", "action": "block_ip"}}]
        response = client.get("/api/soar/audit-log")
        assert response.status_code == 200
        data = response.json()
        assert "entries" in data
        assert "total" in data

    def test_get_audit_log_with_filters(self):
        mock_neo4j._run_query.return_value = []
        response = client.get("/api/soar/audit-log?user_filter=test_admin&action_filter=block_ip")
        assert response.status_code == 200
        assert mock_neo4j._run_query.called

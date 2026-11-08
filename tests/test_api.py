from pathlib import Path

from conftest import TEST_PASSWORD
from fastapi.testclient import TestClient

from utilityaudit.api import create_app
from utilityaudit.auth import Auth
from utilityaudit.ingestion import MAX_BYTES


def client_for(repo):
    client = TestClient(create_app(repo.db))
    login = client.post("/auth/login", json={"username": repo.identity.username, "password": TEST_PASSWORD})
    assert login.status_code == 200
    client.headers["Authorization"] = "Bearer " + login.json()["access_token"]
    return client


def test_complete_api_upload_review_correct_snapshot_delete(repo):
    with client_for(repo) as client:
        root = f"/organizations/{repo.organization_id}"
        assert client.get("/me").json()["organizations"][0]["id"] == repo.organization_id
        response = client.post(
            root + "/documents", files={"file": ("bills.csv", Path("samples/bills.csv").read_bytes(), "text/csv")}
        )
        assert response.status_code == 201 and response.json()["bills_imported"] == 4
        bills = client.get(root + "/bills").json()
        assert bills[0]["account_number"] == "****3456"
        assert "00123456" not in client.get(root + "/bills").text
        finding = next(
            item
            for item in client.get(root + "/analysis").json()["findings"]
            if item["code"] == "arithmetic_discrepancy"
        )
        assert (
            client.put(
                root + f"/findings/{finding['key']}/review",
                json={"status": "verified", "note": "Checked charge arithmetic against source.", "expected_version": 0},
            ).status_code
            == 204
        )
        run = client.post(root + "/audits", json={})
        assert run.status_code == 201, run.text
        pdf = client.get(root + f"/audits/{run.json()['id']}/report")
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
        changed = client.patch(
            root + f"/bills/{bills[-1]['id']}",
            json={
                "expected_version": 1,
                "changes": {"total_due": "358"},
                "reason": "Corrected the total after checking the source CSV.",
            },
        )
        assert changed.status_code == 200 and changed.json()["version"] == 2
        assert client.get(root + f"/audits/{run.json()['id']}/report").content == pdf.content
        document = client.get(root + "/documents").json()[0]
        assert client.delete(root + f"/documents/{document['id']}").status_code == 204
        assert client.get(root + f"/audits/{run.json()['id']}/report").status_code == 404


def test_api_no_auth_and_cross_tenant_access_denied(repo):
    with TestClient(create_app(repo.db)) as client:
        assert client.get(f"/organizations/{repo.organization_id}/bills").status_code == 401
        assert client.get("/health/ready").json() == {"status": "ready"}
    auth = Auth(repo.db)
    other = auth.create_user("other", TEST_PASSWORD)
    org = auth.create_organization(other, "Other")
    with client_for(repo) as client:
        assert client.get(f"/organizations/{org}/bills").status_code == 403
        client.post("/auth/logout")
        assert client.get("/me").status_code == 401


def test_api_bounds_validation_and_sensitive_error_redaction(repo):
    with client_for(repo) as client:
        root = f"/organizations/{repo.organization_id}"
        assert client.post(root + "/documents", files={"file": ("bad.csv", b"total_due\nNaN")}).status_code == 422
        assert (
            client.post(
                root + "/documents", content=b"x", headers={"Content-Length": str(MAX_BYTES + 100000)}
            ).status_code
            == 413
        )
        response = client.post("/auth/login", json={"username": "abc", "password": "do-not-echo" * 30})
        assert response.status_code == 422 and "do-not-echo" not in response.text
        response = client.get("/health/live")
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-request-id"]

        def multipart_chunks():
            yield b'--BOUNDARY\r\nContent-Disposition: form-data; name="file"; filename="big.csv"\r\nContent-Type: text/csv\r\n\r\n'
            for _ in range(11):
                yield b"x" * 1024 * 1024
            yield b"\r\n--BOUNDARY--\r\n"

        response = client.post(
            root + "/documents",
            content=multipart_chunks(),
            headers={"Content-Type": "multipart/form-data; boundary=BOUNDARY"},
        )
        assert response.status_code == 413
        response = client.put(root + "/settings", json={"arithmetic_tolerance": "not-money"})
        assert response.status_code == 422

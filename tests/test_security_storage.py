from pathlib import Path

import pytest
from conftest import TEST_PASSWORD
from cryptography.fernet import Fernet
from sqlalchemy import select, update
from test_ingestion import pdf_bytes

from utilityaudit import database as tables
from utilityaudit.auth import Auth
from utilityaudit.crypto import Cipher
from utilityaudit.errors import AccessDenied, AuthenticationError, Conflict, DataIntegrityError, NotFound
from utilityaudit.models import AuditConfig
from utilityaudit.storage import Repository


def seed(repo):
    repo.import_document("sample.csv", Path("samples/bills.csv").read_bytes())
    return repo.bills()


def test_tenant_isolation_and_scoped_duplicate_hash(repo):
    seed(repo)
    auth = Auth(repo.db)
    second = auth.create_user("other-owner", TEST_PASSWORD)
    other_org = auth.create_organization(second, "Other organization")
    other = Repository(repo.db, second, other_org)
    seed(other)
    document_id = other.documents()[0]["id"]
    with pytest.raises(NotFound):
        repo.document_content(document_id)
    with pytest.raises(NotFound):
        repo.delete_document(document_id)
    with pytest.raises(AccessDenied):
        Repository(repo.db, repo.identity, other_org).bills()
    assert len(repo.bills()) == len(other.bills()) == 4
    with pytest.raises(ValueError):
        repo.run_audit([other.bills()[0].id])


def test_roles_and_membership_revocation_are_checked_each_operation(repo):
    seed(repo)
    auth = Auth(repo.db)
    user = auth.create_user("viewer-user", TEST_PASSWORD)
    auth.set_membership(repo.identity, repo.organization_id, user.username, "viewer")
    viewer = Repository(repo.db, user, repo.organization_id)
    assert len(viewer.bills()) == 4
    for action in (
        lambda: viewer.import_document("a.csv", b"total_due\n1"),
        lambda: viewer.save_config(AuditConfig()),
        lambda: viewer.document_content(repo.documents()[0]["id"]),
        lambda: viewer.delete_document(repo.documents()[0]["id"]),
    ):
        with pytest.raises(AccessDenied):
            action()
    auth.set_membership(repo.identity, repo.organization_id, user.username, None)
    with pytest.raises(AccessDenied):
        viewer.bills()
    with pytest.raises(Conflict, match="at least one owner"):
        auth.set_membership(repo.identity, repo.organization_id, repo.identity.username, "viewer")


def test_authentication_logout_password_change_and_throttling(repo):
    auth = Auth(repo.db)
    token = auth.login(repo.identity.username, TEST_PASSWORD)
    assert auth.authenticate(token) == repo.identity
    auth.logout(token)
    with pytest.raises(AuthenticationError):
        auth.authenticate(token)
    token = auth.login(repo.identity.username, TEST_PASSWORD)
    auth.change_password(repo.identity, TEST_PASSWORD, "new-synthetic-test-password")
    with pytest.raises(AuthenticationError):
        auth.authenticate(token)
    for _ in range(5):
        with pytest.raises(AuthenticationError):
            auth.login(repo.identity.username, "incorrect-password")
    with pytest.raises(AuthenticationError, match="temporarily"):
        auth.login(repo.identity.username, "new-synthetic-test-password")
    auth.reset_password(repo.identity.username, "operator-reset-test-password")
    assert auth.authenticate(auth.login(repo.identity.username, "operator-reset-test-password")) == repo.identity
    assert any(event["action"] == "operator.password_reset" and event["username"] is None for event in repo.activity())


def test_corrections_reviews_conflicts_and_snapshot_immutability(repo):
    bills = seed(repo)
    _, result, _ = repo.analysis()
    finding = next(item for item in result.findings if item.code == "arithmetic_discrepancy")
    repo.review(finding.key, "verified", "Verified charge sum against the original CSV source.", expected_version=0)
    _, reviewed, _ = repo.analysis()
    item = next(item for item in reviewed.findings if item.key == finding.key)
    assert item.review_status == "verified" and item.review_version == 1
    with pytest.raises(Conflict):
        repo.review(finding.key, "dismissed", "Another reviewer has changed this finding.", expected_version=0)
    run_id = repo.run_audit()
    original_report = repo.report(run_id, "pdf")
    corrected = repo.correct(
        bills[-1].id,
        {"total_due": "358"},
        [],
        expected_version=1,
        reason="Corrected transcription using the original CSV charge totals.",
    )
    assert corrected.version == 2
    assert repo.report(run_id, "pdf") == original_report
    with pytest.raises(Conflict):
        repo.correct(
            bills[-1].id,
            {"total_due": "350"},
            [],
            expected_version=1,
            reason="Stale editor should not overwrite changes.",
        )
    with pytest.raises(Conflict):
        repo.review(finding.key, "verified", "This finding is no longer current.", expected_version=1)
    assert repo.revision_history(bills[-1].id)[0]["before"]["total_due"] == "380"
    assert all(item.review_status == "unresolved" for item in repo.analysis()[1].findings)
    repo.delete_document(repo.documents()[0]["id"])
    with pytest.raises(NotFound, match="purged"):
        repo.report(run_id, "pdf")
    with repo.db.engine.connect() as connection:
        assert not connection.execute(select(tables.revisions.c.id)).first()
        assert not connection.execute(select(tables.reviews.c.id)).first()


def test_sensitive_payloads_are_encrypted_and_context_bound(repo):
    seed(repo)
    raw = repo.db.path.read_bytes()
    assert b"00123456" not in raw and b"Synthetic Workshop" not in raw
    with repo.db.engine.begin() as connection:
        rows = list(connection.execute(select(tables.bills.c.id, tables.bills.c.payload)).mappings())
        connection.execute(
            update(tables.bills).where(tables.bills.c.id == rows[1]["id"]).values(payload=rows[0]["payload"])
        )
    with pytest.raises(DataIntegrityError):
        repo.bills()
    with pytest.raises(DataIntegrityError):
        Cipher([Fernet.generate_key()]).decrypt(rows[0]["payload"], repo._context("bill", rows[0]["id"]))


def test_retention_preview_and_apply_purge_dependent_reports(repo):
    seed(repo)
    repo.run_audit()
    repo.set_retention(30)
    with repo.db.engine.begin() as connection:
        connection.execute(update(tables.documents).values(uploaded_at="2020-01-01T00:00:00+00:00"))
    assert len(repo.purge_expired()) == 1
    assert len(repo.bills()) == 4
    assert len(repo.purge_expired(apply=True)) == 1
    assert repo.bills() == []
    assert repo.recent_runs()[0]["purged_at"]


def test_pdf_correction_requires_a_real_source_page(repo):
    repo.import_document("source.pdf", pdf_bytes("Total Due: 10\nCurrency: USD"))
    bill = repo.bills()[0]
    with pytest.raises(ValueError, match="source page"):
        repo.correct(
            bill.id,
            {"total_due": "12"},
            [],
            expected_version=1,
            reason="Verified correction from the PDF source.",
            source_page=2,
        )
    assert repo.get_bill(bill.id).version == 1
    revised = repo.correct(
        bill.id,
        {"total_due": "12"},
        [],
        expected_version=1,
        reason="Verified correction from the PDF source.",
        source_page=1,
    )
    assert revised.provenance["total_due"][-1]["page"] == 1

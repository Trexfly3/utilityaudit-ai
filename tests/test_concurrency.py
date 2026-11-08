from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from conftest import TEST_PASSWORD
from sqlalchemy import update

from utilityaudit import auth as auth_module
from utilityaudit import database as tables
from utilityaudit.auth import Auth
from utilityaudit.database import migrate
from utilityaudit.errors import AuthenticationError, ConfigurationError, Conflict


def test_simultaneous_editors_cannot_overwrite_each_other(repo):
    repo.import_document("bills.csv", Path("samples/bills.csv").read_bytes())
    bill = repo.bills()[0]

    def save(amount):
        try:
            return repo.correct(
                bill.id,
                {"total_due": amount},
                [],
                expected_version=1,
                reason="Concurrent editor checked the source document.",
            ).version
        except Conflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(save, ["151", "152"]))
    assert results.count(2) == results.count("conflict") == 1
    assert len(repo.revision_history(bill.id)) == 1


def test_simultaneous_owner_changes_preserve_an_owner(repo):
    auth = Auth(repo.db)
    other = auth.create_user("second-owner", TEST_PASSWORD)
    auth.set_membership(repo.identity, repo.organization_id, other.username, "owner")

    def demote(identity):
        try:
            auth.set_membership(identity, repo.organization_id, identity.username, "auditor")
            return "changed"
        except Conflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(demote, [repo.identity, other]))
    assert results.count("changed") == results.count("conflict") == 1


def test_password_reset_during_login_cannot_create_an_old_credential_session(repo, monkeypatch):
    auth = Auth(repo.db)
    original = auth_module.password_matches

    def reset_after_check(password, encoded):
        matches = original(password, encoded)
        auth.reset_password(repo.identity.username, "replacement-test-password")
        return matches

    monkeypatch.setattr(auth_module, "password_matches", reset_after_check)
    with pytest.raises(AuthenticationError, match="changed"):
        auth.login(repo.identity.username, TEST_PASSWORD)


def test_future_schema_version_fails_closed(repo):
    with repo.db.engine.begin() as connection:
        connection.execute(update(tables.schema_version).values(version=999))
    with pytest.raises(ConfigurationError, match="Unsupported"):
        migrate(repo.db.engine)

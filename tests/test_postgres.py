import os
from pathlib import Path
from uuid import uuid4

import pytest
from conftest import TEST_PASSWORD
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, text

from utilityaudit.auth import Auth
from utilityaudit.crypto import Cipher
from utilityaudit.database import Database, migrate
from utilityaudit.errors import Conflict
from utilityaudit.operations import backup_database, restore_postgres, verify_database
from utilityaudit.storage import Repository


@pytest.mark.postgres
def test_postgres_isolation_reviews_migration_and_recovery(tmp_path):
    url = os.environ.get("UTILITYAUDIT_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("Set UTILITYAUDIT_TEST_POSTGRES_URL to a disposable PostgreSQL admin database.")
    admin = create_engine(url, isolation_level="AUTOCOMMIT", hide_parameters=True)
    name = "utilityaudit_test_" + uuid4().hex
    restore_name = name + "_restore"
    created = []
    primary = restored = None
    try:
        with admin.connect() as connection:
            for database_name in (name, restore_name):
                connection.execute(text(f'CREATE DATABASE "{database_name}"'))
                created.append(database_name)
        target_url = admin.url.set(database=name).render_as_string(hide_password=False)
        cipher = Cipher([Fernet.generate_key()])
        primary = Database(target_url, cipher)
        migrate(primary.engine)
        auth = Auth(primary)
        identity, organization_id = auth.bootstrap("pg-owner", TEST_PASSWORD, "PostgreSQL test")
        repo = Repository(primary, identity, organization_id)
        repo.import_document("bills.csv", Path("samples/bills.csv").read_bytes())
        bill = repo.bills()[0]
        repo.correct(
            bill.id, {"total_due": "151"}, [], expected_version=1, reason="Synthetic PostgreSQL correction regression."
        )
        with pytest.raises(Conflict):
            repo.correct(
                bill.id,
                {"total_due": "152"},
                [],
                expected_version=1,
                reason="Stale writes must fail on PostgreSQL as well.",
            )
        other_org = auth.create_organization(identity, "Second tenant")
        assert Repository(primary, identity, other_org).bills() == []
        token = auth.login(identity.username, TEST_PASSWORD)
        assert auth.authenticate(token) == identity
        run_id = repo.run_audit()
        backup = tmp_path / "postgres.dump"
        backup_database(primary, backup)
        restored = restore_postgres(
            backup, admin.url.set(database=restore_name).render_as_string(hide_password=False), cipher
        )
        recovered = Repository(restored, identity, organization_id)
        assert recovered.report(run_id, "csv") == repo.report(run_id, "csv")
        assert verify_database(restored)["authenticated_payloads"] > 6
    finally:
        if restored:
            restored.engine.dispose()
        if primary:
            primary.engine.dispose()
        with admin.connect() as connection:
            for database_name in created:
                connection.execute(text(f'DROP DATABASE "{database_name}" WITH (FORCE)'))
        admin.dispose()

from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from utilityaudit.auth import Auth
from utilityaudit.crypto import Cipher
from utilityaudit.database import Database
from utilityaudit.storage import Repository

TEST_PASSWORD = "synthetic-test-password-only"


def make_repository(path: Path) -> Repository:
    database = Database(f"sqlite:///{path}", Cipher([Fernet.generate_key()]))
    identity, organization_id = Auth(database).bootstrap("test-owner", TEST_PASSWORD, "Synthetic organization")
    return Repository(database, identity, organization_id)


@pytest.fixture
def repo(tmp_path):
    result = make_repository(tmp_path / "test.sqlite3")
    yield result
    result.db.engine.dispose()

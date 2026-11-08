import json
import sqlite3
from pathlib import Path

import pytest
from conftest import TEST_PASSWORD
from cryptography.fernet import Fernet

from utilityaudit.auth import Auth
from utilityaudit.crypto import Cipher
from utilityaudit.errors import AuthenticationError, Conflict, DataIntegrityError
from utilityaudit.evaluation import evaluate
from utilityaudit.ingestion import ingest
from utilityaudit.models import bill_to_json
from utilityaudit.operations import (
    backup_database,
    import_legacy,
    restore_sqlite,
    rotate_encryption,
    verify_database,
)
from utilityaudit.storage import Repository


def test_backup_restore_and_session_revocation(repo, tmp_path):
    repo.import_document("bills.csv", Path("samples/bills.csv").read_bytes())
    run_id = repo.run_audit()
    token = Auth(repo.db).login(repo.identity.username, TEST_PASSWORD)
    backup = tmp_path / "backup.sqlite3"
    manifest = backup_database(repo.db, backup)
    assert manifest["keys_included"] is False
    with pytest.raises(Conflict):
        backup_database(repo.db, backup)
    restored = restore_sqlite(backup, tmp_path / "restored.sqlite3", repo.db.cipher)
    recovered = Repository(restored, repo.identity, repo.organization_id)
    assert len(recovered.bills()) == 4
    assert recovered.report(run_id, "pdf") == repo.report(run_id, "pdf")
    with pytest.raises(AuthenticationError):
        Auth(restored).authenticate(token)
    assert verify_database(restored)["authenticated_payloads"] > 4
    restored.engine.dispose()
    backup.write_bytes(backup.read_bytes() + b"tampered")
    with pytest.raises(DataIntegrityError, match="checksum"):
        restore_sqlite(backup, tmp_path / "bad.sqlite3", repo.db.cipher)


def test_rotation_preserves_data_and_drops_old_key_requirement(repo):
    old_key = Fernet.generate_key()
    repo.db.cipher = Cipher([old_key])
    repo.import_document("bills.csv", Path("samples/bills.csv").read_bytes())
    new_key = Fernet.generate_key()
    repo.db.cipher = Cipher([new_key, old_key])
    assert rotate_encryption(repo.db) >= 6
    repo.db.cipher = Cipher([new_key])
    assert len(repo.bills()) == 4
    assert verify_database(repo.db)["authenticated_payloads"] >= 6


def test_legacy_import_is_explicit_atomic_and_leaves_source_untouched(repo, tmp_path):
    source = tmp_path / "legacy.sqlite3"
    data = Path("samples/bills.csv").read_bytes()
    document_id, digest, bills = ingest("old.csv", data)
    with sqlite3.connect(source) as connection:
        connection.executescript("""
            CREATE TABLE documents(id TEXT, name TEXT, content BLOB, uploaded_at TEXT);
            CREATE TABLE bills(id TEXT, document_id TEXT, payload TEXT);
        """)
        connection.execute("INSERT INTO documents VALUES (?,?,?,?)", (document_id, "old.csv", data, "2026-01-01"))
        for bill in bills:
            payload = json.loads(bill_to_json(bill))
            for name in ("provenance", "version", "current_charges", "payments", "credits", "previous_balance"):
                del payload[name]
            connection.execute("INSERT INTO bills VALUES (?,?,?)", (bill.id, document_id, json.dumps(payload)))
    before = source.read_bytes()
    assert import_legacy(repo, source) == 4
    assert source.read_bytes() == before
    assert repo.bills()[0].account_number == "00123456"
    assert "v1" in repo.bills()[0].warnings[-1]
    with pytest.raises(ValueError):
        import_legacy(repo, source)
    assert len(repo.bills()) == 4


def test_evaluation_distinguishes_synthetic_evidence_from_real_validation(tmp_path):
    result = evaluate(Path("samples/ground_truth.json"))
    assert result["fields_correct"] == result["fields_evaluated"] == 12
    assert result["finding_precision"] == result["finding_recall"] == 1
    assert "not real-bill accuracy" in result["validation_scope"]
    manifest = tmp_path / "truth.json"
    manifest.write_text(json.dumps({"dataset_kind": "authorized_real", "files": ["bills.csv"]}))
    with pytest.raises(ValueError, match="permission"):
        evaluate(manifest)
    manifest.write_text(json.dumps({"dataset_kind": "synthetic", "files": ["../outside.csv"]}))
    with pytest.raises(ValueError, match="inside"):
        evaluate(manifest)

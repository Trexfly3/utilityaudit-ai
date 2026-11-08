"""Operator-only recovery and migration operations; no public administrative bypass."""

import hashlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, delete, inspect, select, update
from sqlalchemy.engine import make_url

from utilityaudit import database as tables
from utilityaudit.crypto import Cipher
from utilityaudit.database import SCHEMA_VERSION, Database, utc_now
from utilityaudit.errors import ConfigurationError, Conflict, DataIntegrityError
from utilityaudit.models import bill_from_json
from utilityaudit.storage import Repository

ENCRYPTED_COLUMNS = (
    (tables.documents, "name", "name"),
    (tables.documents, "content", "document"),
    (tables.bills, "payload", "bill"),
    (tables.revisions, "payload", "revision"),
    (tables.reviews, "payload", "review"),
    (tables.settings, "payload", "settings"),
    (tables.runs, "payload", "run"),
    (tables.runs, "pdf", "pdf"),
    (tables.runs, "csv", "csv"),
)


def verify_database(database: Database) -> dict[str, int]:
    checked = 0
    with database.engine.connect() as connection:
        if database.path:
            if connection.exec_driver_sql("PRAGMA integrity_check").scalar_one() != "ok":
                raise DataIntegrityError("SQLite integrity check failed.")
            if connection.exec_driver_sql("PRAGMA foreign_key_check").first():
                raise DataIntegrityError("Foreign key integrity check failed.")
        for table, column, kind in ENCRYPTED_COLUMNS:
            for row in connection.execute(select(table)).mappings():
                if row[column] is not None:
                    identifier = row["organization_id"] if table is tables.settings else row["id"]
                    database.cipher.decrypt(row[column], f"{row['organization_id']}:{kind}:{identifier}")
                    checked += 1
    return {"authenticated_payloads": checked, "schema_version": SCHEMA_VERSION}


def checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pg_environment(url: str) -> dict[str, str]:
    parsed = make_url(url)
    env = {key: value for key, value in os.environ.items() if key in ("PATH", "LANG", "HOME", "SYSTEMROOT")}
    values = {
        "PGHOST": parsed.host,
        "PGPORT": parsed.port,
        "PGUSER": parsed.username,
        "PGPASSWORD": parsed.password,
        "PGDATABASE": parsed.database,
    }
    for query, name in (
        ("sslmode", "PGSSLMODE"),
        ("sslrootcert", "PGSSLROOTCERT"),
        ("sslcert", "PGSSLCERT"),
        ("sslkey", "PGSSLKEY"),
    ):
        values[name] = parsed.query.get(query)
    env.update({key: str(value) for key, value in values.items() if value is not None})
    return env


def backup_database(database: Database, output: Path) -> dict:
    verify_database(database)
    manifest_path = output.with_name(output.name + ".json")
    if output.exists() or manifest_path.exists():
        raise Conflict("Backup output and manifest paths must not already exist.")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    try:
        if database.path:
            with sqlite3.connect(database.path) as source, sqlite3.connect(output) as target:
                source.backup(target)
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise DataIntegrityError("Backup integrity check failed.")
            format = "sqlite"
        else:
            subprocess.run(
                ["pg_dump", "--format=custom", "--no-owner", "--no-acl", f"--file={output}"],
                env=pg_environment(database.engine.url.render_as_string(hide_password=False)),
                check=True,
                capture_output=True,
            )
            format = "postgresql-custom"
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "created_at": utc_now(),
            "format": format,
            "sha256": checksum(output),
            "keys_included": False,
        }
        with os.fdopen(os.open(manifest_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as stream:
            json.dump(manifest, stream, indent=2)
        return manifest
    except (OSError, subprocess.CalledProcessError, DataIntegrityError) as exc:
        output.unlink(missing_ok=True)
        raise ConfigurationError(
            "Backup failed. Check disk permissions, database access and matching pg_dump availability."
        ) from exc


def checked_manifest(backup: Path, expected_format: str) -> dict:
    manifest = json.loads(backup.with_name(backup.name + ".json").read_text())
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("format") != expected_format:
        raise DataIntegrityError("Backup schema or format does not match this restore command.")
    if manifest.get("sha256") != checksum(backup):
        raise DataIntegrityError("Backup checksum mismatch. Do not restore this file.")
    return manifest


def restore_sqlite(backup: Path, output: Path, cipher: Cipher) -> Database:
    checked_manifest(backup, "sqlite")
    if output.exists():
        raise Conflict("Restore refuses to overwrite an existing database. Choose a new path.")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    with sqlite3.connect(f"{backup.resolve().as_uri()}?mode=ro", uri=True) as source, sqlite3.connect(output) as target:
        source.backup(target)
    restored = Database(f"sqlite:///{output}", cipher)
    verify_database(restored)
    with restored.engine.begin() as connection:
        connection.execute(delete(tables.sessions))
    return restored


def restore_postgres(backup: Path, target_url: str, cipher: Cipher) -> Database:
    checked_manifest(backup, "postgresql-custom")
    if make_url(target_url).get_backend_name() != "postgresql":
        raise ConfigurationError("PostgreSQL restore requires a PostgreSQL target.")
    engine = create_engine(target_url, hide_parameters=True)
    try:
        if inspect(engine).get_table_names():
            raise Conflict("PostgreSQL restore requires an empty, separately provisioned database.")
    finally:
        engine.dispose()
    try:
        subprocess.run(
            [
                "pg_restore",
                "--single-transaction",
                "--exit-on-error",
                "--no-owner",
                "--no-acl",
                "--dbname",
                make_url(target_url).database,
                str(backup),
            ],
            env=pg_environment(target_url),
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ConfigurationError(
            "PostgreSQL restore failed; check client version, target access and backup integrity."
        ) from exc
    restored = Database(target_url, cipher)
    verify_database(restored)
    with restored.engine.begin() as connection:
        connection.execute(delete(tables.sessions))
    return restored


def rotate_encryption(database: Database) -> int:
    count = 0
    with database.engine.begin() as connection:
        if database.path:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        else:
            names = ", ".join(sorted({table.name for table, _, _ in ENCRYPTED_COLUMNS}))
            connection.exec_driver_sql(f"LOCK TABLE {names} IN EXCLUSIVE MODE")
        for table, column, kind in ENCRYPTED_COLUMNS:
            for row in connection.execute(select(table)).mappings():
                if row[column] is None:
                    continue
                identifier = row["organization_id"] if table is tables.settings else row["id"]
                context = f"{row['organization_id']}:{kind}:{identifier}"
                raw = database.cipher.decrypt(row[column], context)
                id_column = table.c.organization_id if table is tables.settings else table.c.id
                connection.execute(
                    update(table).where(id_column == identifier).values({column: database.cipher.encrypt(raw, context)})
                )
                count += 1
    return count


def import_legacy(repo: Repository, source_path: Path) -> int:
    if repo.db.path and source_path.resolve() == repo.db.path.resolve():
        raise ValueError("Legacy source and destination must be different files.")
    source = sqlite3.connect(f"{source_path.resolve().as_uri()}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    try:
        documents = list(source.execute("SELECT id, name, content FROM documents ORDER BY uploaded_at"))
        with repo.connect("admin", write=True) as connection:
            imported = 0
            for document in documents:
                document_id = str(uuid4())
                parsed = []
                for row in source.execute(
                    "SELECT payload FROM bills WHERE document_id=? ORDER BY rowid", (document["id"],)
                ):
                    bill = bill_from_json(row["payload"])
                    bill.id, bill.document_id = str(uuid4()), document_id
                    bill.warnings.append(
                        "Imported from v1; original provenance was not recorded. Verify against the retained source."
                    )
                    parsed.append(bill)
                if not parsed:
                    raise DataIntegrityError(
                        "Legacy document has no bills. Resolve the legacy database inconsistency first."
                    )
                data = bytes(document["content"])
                repo._insert_document(
                    connection, document_id, hashlib.sha256(data).hexdigest(), document["name"], data, parsed
                )
                imported += len(parsed)
            repo._event(connection, "legacy.imported", repo.organization_id)
        return imported
    finally:
        source.close()

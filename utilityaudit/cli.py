"""Operator commands. Passwords are prompted, never accepted in command arguments."""

import argparse
import getpass
import json
import logging
import os
import sqlite3
import sys
from importlib.metadata import distributions
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from utilityaudit.auth import Auth
from utilityaudit.crypto import load_cipher
from utilityaudit.database import runtime_database
from utilityaudit.errors import ApplicationError, ConfigurationError
from utilityaudit.evaluation import evaluate
from utilityaudit.operations import (
    backup_database,
    import_legacy,
    restore_postgres,
    restore_sqlite,
    rotate_encryption,
    verify_database,
)
from utilityaudit.storage import Repository


def new_password() -> str:
    password = getpass.getpass("New password: ")
    if password != getpass.getpass("Confirm password: "):
        raise ValueError("Passwords do not match.")
    return password


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="utilityaudit")
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap = commands.add_parser("bootstrap", help="Create the first owner; disabled after any user exists")
    bootstrap.add_argument("--username", required=True)
    bootstrap.add_argument("--organization", required=True)
    user = commands.add_parser("user-add", help="Operator-only user creation; membership is assigned separately")
    user.add_argument("--username", required=True)
    reset = commands.add_parser("user-reset", help="Operator-only password recovery; revokes all sessions")
    reset.add_argument("--username", required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("--output", type=Path, required=True)
    restore = commands.add_parser("restore-sqlite")
    restore.add_argument("--backup", type=Path, required=True)
    restore.add_argument("--output", type=Path, required=True)
    pg_restore = commands.add_parser("restore-postgres")
    pg_restore.add_argument("--backup", type=Path, required=True)
    pg_restore.add_argument("--target-env", default="UTILITYAUDIT_RESTORE_DATABASE_URL")
    commands.add_parser("verify-data")
    rotate = commands.add_parser("rotate-keys")
    rotate.add_argument("--offline-confirm", action="store_true", required=True)
    legacy = commands.add_parser("import-legacy")
    legacy.add_argument("--source", type=Path, required=True)
    for command in (legacy, commands.add_parser("purge-expired")):
        command.add_argument("--username", required=True)
        command.add_argument("--organization-id", required=True)
        if command is not legacy:
            command.add_argument(
                "--apply", action="store_true", help="Delete expired sources and dependent report contents"
            )
    evaluation = commands.add_parser("evaluate")
    evaluation.add_argument("manifest", type=Path)
    commands.add_parser("licenses", help="Inventory installed distributions; not a legal approval")
    commands.add_parser("migrate", help="Apply supported schema migrations")
    api = commands.add_parser("serve-api")
    api.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    try:
        if args.command == "evaluate":
            print(json.dumps(evaluate(args.manifest), indent=2))
            return
        if args.command == "licenses":
            print(
                json.dumps(
                    sorted(
                        [
                            {
                                "name": item.metadata["Name"],
                                "version": item.version,
                                "license": (
                                    item.metadata.get("License-Expression")
                                    or item.metadata.get("License")
                                    or "REVIEW REQUIRED"
                                )[:300],
                            }
                            for item in distributions()
                        ],
                        key=lambda item: item["name"].casefold(),
                    ),
                    indent=2,
                )
            )
            return
        if args.command == "serve-api":
            import uvicorn

            logging.basicConfig(level=logging.INFO, format="%(message)s")
            uvicorn.run(
                "utilityaudit.api:create_app",
                factory=True,
                host="127.0.0.1",
                port=args.port,
                access_log=False,
                proxy_headers=True,
                forwarded_allow_ips=os.environ.get("UTILITYAUDIT_TRUSTED_PROXIES", "127.0.0.1"),
            )
            return
        if args.command.startswith("restore-"):
            directory = Path(os.environ.get("UTILITYAUDIT_DATA_DIR", str(Path(__file__).resolve().parents[1] / "data")))
            if not os.environ.get("UTILITYAUDIT_ENCRYPTION_KEYS") and not (directory / "encryption.key").exists():
                raise ConfigurationError("Restore the original encryption key separately before restoring data.")
            cipher = load_cipher(directory, server_mode=os.environ.get("UTILITYAUDIT_MODE") == "server")
            if args.command == "restore-sqlite":
                restored = restore_sqlite(args.backup, args.output, cipher)
            else:
                url = os.environ.get(args.target_env)
                if not url:
                    raise ConfigurationError("Set the target database URL in the named environment variable.")
                restored = restore_postgres(args.backup, url, cipher)
            print(json.dumps({"restored": True, **verify_database(restored), "sessions_revoked": True}))
            restored.engine.dispose()
            return
        database = runtime_database()
        auth = Auth(database)
        if args.command == "bootstrap":
            identity, organization_id = auth.bootstrap(args.username, new_password(), args.organization)
            print(json.dumps({"username": identity.username, "organization_id": organization_id}))
        elif args.command == "user-add":
            identity = auth.create_user(args.username, new_password())
            print(json.dumps({"username": identity.username, "membership": "not yet assigned"}))
        elif args.command == "user-reset":
            auth.reset_password(args.username, new_password())
            print(json.dumps({"password_reset": True, "sessions_revoked": True, "actor": "operator CLI"}))
        elif args.command == "backup":
            print(json.dumps(backup_database(database, args.output), indent=2))
        elif args.command == "verify-data":
            print(json.dumps(verify_database(database)))
        elif args.command == "rotate-keys":
            print(json.dumps({"payloads_reencrypted": rotate_encryption(database)}))
        elif args.command == "migrate":
            print(json.dumps({"schema": "current"}))
        elif args.command in ("import-legacy", "purge-expired"):
            token = auth.login(args.username, getpass.getpass("Owner password: "))
            try:
                identity = auth.authenticate(token)
                repo = Repository(database, identity, args.organization_id)
                if args.command == "import-legacy":
                    print(json.dumps({"bills_imported": import_legacy(repo, args.source)}))
                else:
                    ids = repo.purge_expired(apply=args.apply)
                    print(json.dumps({"apply": args.apply, "document_count": len(ids)}))
            finally:
                auth.logout(token)
        database.engine.dispose()
    except (ApplicationError, ValueError, OSError, sqlite3.Error, SQLAlchemyError) as exc:
        message = (
            str(exc)
            if isinstance(exc, (ApplicationError, ValueError))
            else (f"{type(exc).__name__}: operation failed; check permissions, connectivity and configuration.")
        )
        print(message, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()

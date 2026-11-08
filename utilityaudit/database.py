"""Versioned SQLAlchemy schema for SQLite and PostgreSQL."""

import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    create_engine,
    event,
    select,
)
from sqlalchemy.engine import Connection, Engine, make_url

from utilityaudit.crypto import Cipher, load_cipher
from utilityaudit.errors import ConfigurationError

metadata = MetaData()
schema_version = Table("ua_schema_version", metadata, Column("version", Integer, primary_key=True))
users = Table(
    "ua_users",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("username", String(64), unique=True, nullable=False),
    Column("password_hash", String(256), nullable=False),
    Column("active", Boolean, nullable=False),
)
organizations = Table(
    "ua_organizations",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(120), nullable=False),
    Column("retention_days", Integer, nullable=True),
    Column("created_at", String(40), nullable=False),
)
memberships = Table(
    "ua_memberships",
    metadata,
    Column("organization_id", ForeignKey("ua_organizations.id"), primary_key=True),
    Column("user_id", ForeignKey("ua_users.id"), primary_key=True),
    Column("role", String(20), nullable=False),
)
sessions = Table(
    "ua_sessions",
    metadata,
    Column("token_hash", String(64), primary_key=True),
    Column("user_id", ForeignKey("ua_users.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("expires_at", Integer, nullable=False),
    Column("last_seen", Integer, nullable=False),
)
login_limits = Table(
    "ua_login_limits",
    metadata,
    Column("key", String(64), primary_key=True),
    Column("attempts", Integer, nullable=False),
    Column("window_start", Integer, nullable=False),
)
documents = Table(
    "ua_documents",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", ForeignKey("ua_organizations.id"), nullable=False, index=True),
    Column("name", LargeBinary, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("content", LargeBinary, nullable=False),
    Column("byte_count", Integer, nullable=False),
    Column("uploaded_at", String(40), nullable=False),
    UniqueConstraint("organization_id", "sha256"),
    UniqueConstraint("id", "organization_id"),
)
bills = Table(
    "ua_bills",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", ForeignKey("ua_organizations.id"), nullable=False, index=True),
    Column("document_id", String(36), nullable=False),
    Column("payload", LargeBinary, nullable=False),
    Column("version", Integer, nullable=False),
    Column("position", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["document_id", "organization_id"], ["ua_documents.id", "ua_documents.organization_id"], ondelete="CASCADE"
    ),
    UniqueConstraint("id", "organization_id"),
)
revisions = Table(
    "ua_revisions",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", ForeignKey("ua_organizations.id"), nullable=False, index=True),
    Column("bill_id", String(36), nullable=False),
    Column("version", Integer, nullable=False),
    Column("actor_id", ForeignKey("ua_users.id"), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("payload", LargeBinary, nullable=False),
    ForeignKeyConstraint(
        ["bill_id", "organization_id"], ["ua_bills.id", "ua_bills.organization_id"], ondelete="CASCADE"
    ),
    UniqueConstraint("bill_id", "version"),
)
reviews = Table(
    "ua_reviews",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", ForeignKey("ua_organizations.id"), nullable=False, index=True),
    Column("bill_id", String(36), nullable=False),
    Column("finding_key", String(64), nullable=False),
    Column("version", Integer, nullable=False),
    Column("payload", LargeBinary, nullable=False),
    ForeignKeyConstraint(
        ["bill_id", "organization_id"], ["ua_bills.id", "ua_bills.organization_id"], ondelete="CASCADE"
    ),
    UniqueConstraint("organization_id", "finding_key", "version"),
)
settings = Table(
    "ua_settings",
    metadata,
    Column("organization_id", ForeignKey("ua_organizations.id"), primary_key=True),
    Column("payload", LargeBinary, nullable=False),
)
runs = Table(
    "ua_runs",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", ForeignKey("ua_organizations.id"), nullable=False, index=True),
    Column("created_at", String(40), nullable=False),
    Column("bill_count", Integer, nullable=False),
    Column("finding_count", Integer, nullable=False),
    Column("payload", LargeBinary),
    Column("pdf", LargeBinary),
    Column("csv", LargeBinary),
    Column("purged_at", String(40)),
)
run_bills = Table(
    "ua_run_bills",
    metadata,
    Column("run_id", ForeignKey("ua_runs.id", ondelete="CASCADE"), primary_key=True),
    Column("bill_id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False, index=True),
)
events = Table(
    "ua_events",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", ForeignKey("ua_organizations.id"), nullable=False, index=True),
    Column("actor_id", ForeignKey("ua_users.id"), nullable=True),
    Column("action", String(60), nullable=False),
    Column("subject_id", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
)

SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def migrate(engine: Engine) -> None:
    with engine.begin() as connection:
        if engine.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        else:
            connection.exec_driver_sql("SELECT pg_advisory_xact_lock(73510421)")
        schema_version.create(connection, checkfirst=True)
        version = connection.execute(select(schema_version.c.version)).scalar_one_or_none()
        if version is not None and version != SCHEMA_VERSION:
            raise ConfigurationError("Unsupported database schema version. Use the matching application release.")
        if version is None:
            metadata.create_all(connection)
            connection.execute(schema_version.insert().values(version=SCHEMA_VERSION))


class Database:
    def __init__(self, url: str, cipher: Cipher):
        parsed = make_url(url)
        if parsed.get_backend_name() not in ("sqlite", "postgresql"):
            raise ConfigurationError("Only SQLite and PostgreSQL databases are supported.")
        self.path: Path | None = None
        self.cipher = cipher
        options = {"pool_pre_ping": True, "hide_parameters": True}
        if parsed.get_backend_name() == "sqlite":
            if not parsed.database or parsed.database == ":memory:":
                raise ConfigurationError("Use a file-backed SQLite database.")
            self.path = Path(parsed.database)
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            options["connect_args"] = {"check_same_thread": False, "timeout": 30}
        self.engine = create_engine(url, **options)
        if self.path:

            @event.listens_for(self.engine, "connect")
            def sqlite_pragmas(connection, _):
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA secure_delete=ON")

        migrate(self.engine)
        if self.path:
            self.path.chmod(0o600)

    def lock_organization(self, connection: Connection, organization_id: str) -> None:
        connection.execute(
            select(organizations.c.id).where(organizations.c.id == organization_id).with_for_update()
        ).first()


def runtime_database() -> Database:
    directory = Path(os.environ.get("UTILITYAUDIT_DATA_DIR", str(Path(__file__).resolve().parents[1] / "data")))
    mode = os.environ.get("UTILITYAUDIT_MODE", "local")
    if mode not in ("local", "server"):
        raise ConfigurationError("UTILITYAUDIT_MODE must be local or server.")
    url = os.environ.get("UTILITYAUDIT_DATABASE_URL", f"sqlite:///{directory / 'utilityaudit-v2.sqlite3'}")
    if mode == "server":
        from urllib.parse import urlparse

        public_url = urlparse(os.environ.get("UTILITYAUDIT_PUBLIC_URL", ""))
        if public_url.scheme != "https" or not public_url.hostname:
            raise ConfigurationError("Server mode requires an HTTPS UTILITYAUDIT_PUBLIC_URL.")
        parsed = make_url(url)
        if parsed.get_backend_name() != "postgresql" or parsed.query.get("sslmode") != "verify-full":
            raise ConfigurationError("Server mode requires PostgreSQL with sslmode=verify-full.")
    return Database(url, load_cipher(directory, server_mode=mode == "server"))

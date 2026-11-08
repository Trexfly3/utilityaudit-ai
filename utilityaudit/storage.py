"""Organization-scoped repository with authorization at every operation."""

import json
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4

import pymupdf as fitz
from sqlalchemy import delete, func, select, update
from sqlalchemy.engine import Connection

from utilityaudit import database as tables
from utilityaudit.audit import analyze
from utilityaudit.auth import Identity
from utilityaudit.database import Database, utc_now
from utilityaudit.errors import AccessDenied, Conflict, DataIntegrityError, NotFound
from utilityaudit.ingestion import correct_bill, ingest
from utilityaudit.models import (
    RULE_VERSION,
    AuditConfig,
    AuditResult,
    Bill,
    bill_from_json,
    bill_to_json,
    json_default,
)


class DuplicateDocumentError(ValueError):
    pass


class Repository:
    def __init__(self, database: Database, identity: Identity, organization_id: str):
        self.db = database
        self.identity = identity
        self.organization_id = organization_id

    @contextmanager
    def connect(self, permission: str = "read", *, write: bool = False) -> Iterator[Connection]:
        with self.db.engine.begin() as connection:
            if write and self.db.engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            if write:
                self.db.lock_organization(connection, self.organization_id)
            role = connection.execute(
                select(tables.memberships.c.role)
                .join(tables.users)
                .where(
                    tables.memberships.c.organization_id == self.organization_id,
                    tables.memberships.c.user_id == self.identity.user_id,
                    tables.users.c.active.is_(True),
                )
            ).scalar_one_or_none()
            allowed = {
                "read": ("owner", "auditor", "viewer"),
                "edit": ("owner", "auditor"),
                "source": ("owner", "auditor"),
                "admin": ("owner",),
            }
            if role not in allowed[permission]:
                raise AccessDenied("This operation is not permitted for your current organization role.")
            yield connection

    @property
    def role(self) -> str:
        with self.connect() as connection:
            return connection.execute(
                select(tables.memberships.c.role).where(
                    tables.memberships.c.organization_id == self.organization_id,
                    tables.memberships.c.user_id == self.identity.user_id,
                )
            ).scalar_one()

    def _context(self, kind: str, identifier: str) -> str:
        return f"{self.organization_id}:{kind}:{identifier}"

    def _encode(self, kind: str, identifier: str, value: object) -> bytes:
        return self.db.cipher.encrypt(json.dumps(value, default=json_default).encode(), self._context(kind, identifier))

    def _decode(self, kind: str, identifier: str, value: bytes):
        return json.loads(self.db.cipher.decrypt(value, self._context(kind, identifier)))

    def _event(self, connection: Connection, action: str, subject_id: str) -> None:
        connection.execute(
            tables.events.insert().values(
                id=str(uuid4()),
                organization_id=self.organization_id,
                actor_id=self.identity.user_id,
                action=action,
                subject_id=subject_id,
                created_at=utc_now(),
            )
        )

    def _bills(self, connection: Connection) -> list[Bill]:
        result = []
        for row in connection.execute(
            select(tables.bills)
            .where(tables.bills.c.organization_id == self.organization_id)
            .order_by(tables.bills.c.created_at, tables.bills.c.document_id, tables.bills.c.position)
        ).mappings():
            bill = bill_from_json(self.db.cipher.decrypt(row["payload"], self._context("bill", row["id"])).decode())
            if (bill.id, bill.document_id, bill.version) != (row["id"], row["document_id"], row["version"]):
                raise DataIntegrityError("Bill metadata failed integrity validation.")
            result.append(bill)
        return result

    def bills(self) -> list[Bill]:
        with self.connect() as connection:
            return self._bills(connection)

    def get_bill(self, bill_id: str) -> Bill:
        with self.connect() as connection:
            return self._get_bill(connection, bill_id)

    def _get_bill(self, connection: Connection, bill_id: str) -> Bill:
        row = (
            connection.execute(
                select(tables.bills).where(
                    tables.bills.c.organization_id == self.organization_id, tables.bills.c.id == bill_id
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            raise NotFound("Bill not found in this organization.")
        bill = bill_from_json(self.db.cipher.decrypt(row["payload"], self._context("bill", bill_id)).decode())
        if (bill.id, bill.document_id, bill.version) != (row["id"], row["document_id"], row["version"]):
            raise DataIntegrityError("Bill metadata failed integrity validation.")
        return bill

    def import_document(self, filename: str, data: bytes) -> int:
        with self.connect("edit"):
            pass
        document_id, digest, parsed = ingest(filename, data)
        with self.connect("edit", write=True) as connection:
            self._insert_document(connection, document_id, digest, filename, data, parsed)
        return len(parsed)

    def _insert_document(
        self, connection: Connection, document_id: str, digest: str, filename: str, data: bytes, parsed: list[Bill]
    ) -> None:
        if connection.execute(
            select(tables.documents.c.id).where(
                tables.documents.c.organization_id == self.organization_id, tables.documents.c.sha256 == digest
            )
        ).first():
            raise DuplicateDocumentError("This exact document is already uploaded to this organization.")
        count = connection.execute(
            select(func.count()).select_from(tables.bills).where(tables.bills.c.organization_id == self.organization_id)
        ).scalar_one()
        if count + len(parsed) > 5000:
            raise ValueError("This release supports at most 5,000 active bills per organization.")
        name = Path(filename.replace("\\", "/")).name[:200]
        now = utc_now()
        connection.execute(
            tables.documents.insert().values(
                id=document_id,
                organization_id=self.organization_id,
                name=self._encode("name", document_id, name),
                sha256=digest,
                content=self.db.cipher.encrypt(data, self._context("document", document_id)),
                byte_count=len(data),
                uploaded_at=now,
            )
        )
        connection.execute(
            tables.bills.insert(),
            [
                {
                    "id": bill.id,
                    "organization_id": self.organization_id,
                    "document_id": document_id,
                    "payload": self.db.cipher.encrypt(bill_to_json(bill).encode(), self._context("bill", bill.id)),
                    "version": bill.version,
                    "position": position,
                    "created_at": now,
                }
                for position, bill in enumerate(parsed)
            ],
        )
        self._event(connection, "document.imported", document_id)

    def documents(self) -> list[dict]:
        with self.connect() as connection:
            return [
                {
                    "id": row["id"],
                    "name": self._decode("name", row["id"], row["name"]),
                    "uploaded_at": row["uploaded_at"],
                    "bytes": row["byte_count"],
                }
                for row in connection.execute(
                    select(tables.documents)
                    .where(tables.documents.c.organization_id == self.organization_id)
                    .order_by(tables.documents.c.uploaded_at.desc())
                ).mappings()
            ]

    def _document(self, connection: Connection, document_id: str) -> bytes:
        row = connection.execute(
            select(tables.documents.c.content).where(
                tables.documents.c.organization_id == self.organization_id, tables.documents.c.id == document_id
            )
        ).first()
        if row is None:
            raise NotFound("Document not found in this organization.")
        return self.db.cipher.decrypt(row.content, self._context("document", document_id))

    def document_content(self, document_id: str) -> bytes:
        return self.document_download(document_id)[1]

    def document_download(self, document_id: str) -> tuple[str, bytes]:
        with self.connect("source", write=True) as connection:
            data = self._document(connection, document_id)
            encrypted_name = connection.execute(
                select(tables.documents.c.name).where(
                    tables.documents.c.organization_id == self.organization_id, tables.documents.c.id == document_id
                )
            ).scalar_one()
            self._event(connection, "document.accessed", document_id)
            return self._decode("name", document_id, encrypted_name), data

    def _delete_document(self, connection: Connection, document_id: str) -> None:
        bill_ids = select(tables.bills.c.id).where(
            tables.bills.c.organization_id == self.organization_id, tables.bills.c.document_id == document_id
        )
        affected = select(tables.run_bills.c.run_id).where(
            tables.run_bills.c.organization_id == self.organization_id, tables.run_bills.c.bill_id.in_(bill_ids)
        )
        connection.execute(
            update(tables.runs)
            .where(tables.runs.c.organization_id == self.organization_id, tables.runs.c.id.in_(affected))
            .values(payload=None, pdf=None, csv=None, purged_at=utc_now())
        )
        deleted = connection.execute(
            delete(tables.documents).where(
                tables.documents.c.id == document_id, tables.documents.c.organization_id == self.organization_id
            )
        ).rowcount
        if deleted != 1:
            raise NotFound("Document not found in this organization.")
        self._event(connection, "document.deleted", document_id)

    def delete_document(self, document_id: str) -> None:
        with self.connect("admin", write=True) as connection:
            self._delete_document(connection, document_id)

    def correct(
        self,
        bill_id: str,
        changes: dict[str, str],
        verified_fields: list[str],
        *,
        expected_version: int,
        reason: str,
        source_page: int | None = None,
    ) -> Bill:
        if not 10 <= len(reason.strip()) <= 2000:
            raise ValueError("Describe the source evidence and reason in 10 to 2,000 characters.")
        with self.connect("edit", write=True) as connection:
            previous = self._get_bill(connection, bill_id)
            if previous.version != expected_version:
                raise Conflict("Bill changed since you opened it. Reload before saving.")
            revised = correct_bill(previous, changes, verified_fields)
            data = self._document(connection, previous.document_id)
            if data.startswith(b"%PDF-"):
                with fitz.open(stream=data, filetype="pdf") as document:
                    if type(source_page) is not int or not 1 <= source_page <= len(document):
                        raise ValueError("Cite an existing PDF source page for this correction.")
            now, revision_id = utc_now(), str(uuid4())
            for name in set(changes) | set(verified_fields):
                revised.provenance.setdefault(name, []).append(
                    {
                        "kind": "manual",
                        "page": source_page,
                        "row": previous.source_row,
                        "text": reason.strip(),
                        "actor": self.identity.username,
                        "at": now,
                    }
                )
            connection.execute(
                update(tables.bills)
                .where(
                    tables.bills.c.id == bill_id,
                    tables.bills.c.organization_id == self.organization_id,
                    tables.bills.c.version == expected_version,
                )
                .values(
                    version=revised.version,
                    payload=self.db.cipher.encrypt(bill_to_json(revised).encode(), self._context("bill", bill_id)),
                )
            )
            connection.execute(
                tables.revisions.insert().values(
                    id=revision_id,
                    organization_id=self.organization_id,
                    bill_id=bill_id,
                    version=revised.version,
                    actor_id=self.identity.user_id,
                    created_at=now,
                    payload=self._encode(
                        "revision",
                        revision_id,
                        {
                            "before": json.loads(bill_to_json(previous)),
                            "after": json.loads(bill_to_json(revised)),
                            "reason": reason.strip(),
                            "fields": sorted(set(changes) | set(verified_fields)),
                            "source_page": source_page,
                            "actor": self.identity.username,
                        },
                    ),
                )
            )
            self._event(connection, "bill.corrected", bill_id)
            return revised

    def revision_history(self, bill_id: str) -> list[dict]:
        with self.connect("source") as connection:
            self._get_bill(connection, bill_id)
            return [
                {
                    "version": row["version"],
                    "created_at": row["created_at"],
                    **self._decode("revision", row["id"], row["payload"]),
                }
                for row in connection.execute(
                    select(tables.revisions)
                    .where(
                        tables.revisions.c.organization_id == self.organization_id,
                        tables.revisions.c.bill_id == bill_id,
                    )
                    .order_by(tables.revisions.c.version)
                ).mappings()
            ]

    def _config(self, connection: Connection) -> AuditConfig:
        row = connection.execute(
            select(tables.settings.c.payload).where(tables.settings.c.organization_id == self.organization_id)
        ).first()
        return AuditConfig(**self._decode("settings", self.organization_id, row.payload)) if row else AuditConfig()

    def config(self) -> AuditConfig:
        with self.connect() as connection:
            return self._config(connection)

    def save_config(self, config: AuditConfig) -> None:
        config.__post_init__()
        with self.connect("admin", write=True) as connection:
            connection.execute(delete(tables.settings).where(tables.settings.c.organization_id == self.organization_id))
            connection.execute(
                tables.settings.insert().values(
                    organization_id=self.organization_id,
                    payload=self._encode("settings", self.organization_id, asdict(config)),
                )
            )
            self._event(connection, "settings.updated", self.organization_id)

    def _analysis(self, connection: Connection) -> tuple[list[Bill], AuditResult, AuditConfig]:
        bills = self._bills(connection)
        config = self._config(connection)
        result = analyze(bills, config)
        by_key = {item.key: item for item in result.findings}
        for row in connection.execute(
            select(tables.reviews)
            .where(tables.reviews.c.organization_id == self.organization_id)
            .order_by(tables.reviews.c.version)
        ).mappings():
            item = by_key.get(row["finding_key"])
            if item:
                review = self._decode("review", row["id"], row["payload"])
                item.review_status, item.review_note = review["status"], review["note"]
                item.reviewed_by, item.reviewed_at = review["actor"], review["created_at"]
                item.review_version = row["version"]
        return bills, result, config

    def analysis(self) -> tuple[list[Bill], AuditResult, AuditConfig]:
        with self.connect() as connection:
            return self._analysis(connection)

    def review(self, finding_key: str, status: str, note: str, *, expected_version: int) -> None:
        if status not in ("unresolved", "verified", "dismissed"):
            raise ValueError("Review status must be unresolved, verified or dismissed.")
        if not 10 <= len(note.strip()) <= 2000:
            raise ValueError("Record source evidence and reasoning in 10 to 2,000 characters.")
        with self.connect("edit", write=True) as connection:
            _, result, _ = self._analysis(connection)
            item = next((item for item in result.findings if item.key == finding_key), None)
            if item is None:
                raise Conflict("Finding is stale or unavailable. Recalculate before reviewing.")
            if item.review_version != expected_version:
                raise Conflict("Another reviewer changed this finding. Reload before saving.")
            review_id = str(uuid4())
            connection.execute(
                tables.reviews.insert().values(
                    id=review_id,
                    organization_id=self.organization_id,
                    bill_id=item.bill_id,
                    finding_key=finding_key,
                    version=expected_version + 1,
                    payload=self._encode(
                        "review",
                        review_id,
                        {
                            "status": status,
                            "note": note.strip(),
                            "actor": self.identity.username,
                            "created_at": utc_now(),
                        },
                    ),
                )
            )
            self._event(connection, f"finding.{status}", item.bill_id)

    def review_history(self, bill_id: str) -> list[dict]:
        with self.connect() as connection:
            self._get_bill(connection, bill_id)
            history = [
                {
                    "finding_key": row["finding_key"],
                    "version": row["version"],
                    **self._decode("review", row["id"], row["payload"]),
                }
                for row in connection.execute(
                    select(tables.reviews)
                    .where(
                        tables.reviews.c.organization_id == self.organization_id, tables.reviews.c.bill_id == bill_id
                    )
                    .order_by(tables.reviews.c.version, tables.reviews.c.id)
                ).mappings()
            ]
            return sorted(history, key=lambda row: row["created_at"])

    def run_audit(self, bill_ids: list[str] | None = None) -> str:
        from utilityaudit.reports import export_csv, export_pdf

        with self.connect("edit", write=True) as connection:
            all_bills, result, config = self._analysis(connection)
            selected = set(bill_ids) if bill_ids is not None else {bill.id for bill in all_bills}
            if not selected or not selected <= {bill.id for bill in all_bills}:
                raise ValueError("Select existing bills from the current organization.")
            if len(selected) > 500:
                raise ValueError("A report supports at most 500 bills. Narrow its scope.")
            bills = [bill for bill in all_bills if bill.id in selected]
            findings = [item for item in result.findings if item.bill_id in selected]
            coverage = [item for item in result.coverage if item.bill_id in selected]
            run_id, created = str(uuid4()), utc_now()
            context = {
                "snapshot_id": run_id,
                "created_at": created,
                "rule_version": RULE_VERSION,
                "input_digest": result.input_digest,
                "comparison_scope": "All organization bills",
            }
            pdf_data = export_pdf(bills, findings, config, coverage=coverage, context=context)
            csv_data = export_csv(bills, findings, config, coverage=coverage, context=context)
            connection.execute(
                tables.runs.insert().values(
                    id=run_id,
                    organization_id=self.organization_id,
                    created_at=created,
                    bill_count=len(bills),
                    finding_count=len(findings),
                    payload=self._encode(
                        "run",
                        run_id,
                        {
                            "context": context,
                            "bills": [json.loads(bill_to_json(bill)) for bill in bills],
                            "findings": [asdict(item) for item in findings],
                            "coverage": [asdict(item) for item in coverage],
                            "configuration": asdict(config),
                        },
                    ),
                    pdf=self.db.cipher.encrypt(pdf_data, self._context("pdf", run_id)),
                    csv=self.db.cipher.encrypt(csv_data, self._context("csv", run_id)),
                )
            )
            connection.execute(
                tables.run_bills.insert(),
                [{"run_id": run_id, "bill_id": bill.id, "organization_id": self.organization_id} for bill in all_bills],
            )
            self._event(connection, "audit.recorded", run_id)
            return run_id

    def report(self, run_id: str, format: str) -> bytes:
        if format not in ("pdf", "csv"):
            raise ValueError("Report format must be pdf or csv.")
        with self.connect() as connection:
            row = (
                connection.execute(
                    select(tables.runs).where(
                        tables.runs.c.organization_id == self.organization_id, tables.runs.c.id == run_id
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                raise NotFound("Report not found in this organization.")
            if row["purged_at"]:
                raise NotFound("Report contents were purged after source deletion or retention.")
            return self.db.cipher.decrypt(row[format], self._context(format, run_id))

    def recent_runs(self) -> list[dict]:
        with self.connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    select(
                        tables.runs.c.id,
                        tables.runs.c.created_at,
                        tables.runs.c.bill_count,
                        tables.runs.c.finding_count,
                        tables.runs.c.purged_at,
                    )
                    .where(tables.runs.c.organization_id == self.organization_id)
                    .order_by(tables.runs.c.created_at.desc())
                    .limit(50)
                ).mappings()
            ]

    def activity(self) -> list[dict]:
        with self.connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    select(
                        tables.events.c.created_at,
                        tables.events.c.action,
                        tables.events.c.subject_id,
                        tables.users.c.username,
                    )
                    .outerjoin(tables.users)
                    .where(tables.events.c.organization_id == self.organization_id)
                    .order_by(tables.events.c.created_at.desc())
                    .limit(100)
                ).mappings()
            ]

    def retention_days(self) -> int | None:
        with self.connect() as connection:
            return connection.execute(
                select(tables.organizations.c.retention_days).where(tables.organizations.c.id == self.organization_id)
            ).scalar_one()

    def set_retention(self, days: int | None) -> None:
        if days is not None and (type(days) is not int or not 1 <= days <= 3650):
            raise ValueError("Retention must be disabled or between 1 and 3650 days.")
        with self.connect("admin", write=True) as connection:
            connection.execute(
                update(tables.organizations)
                .where(tables.organizations.c.id == self.organization_id)
                .values(retention_days=days)
            )
            self._event(connection, "retention.updated", self.organization_id)

    def purge_expired(self, *, apply: bool = False) -> list[str]:
        with self.connect("admin", write=apply) as connection:
            days = connection.execute(
                select(tables.organizations.c.retention_days).where(tables.organizations.c.id == self.organization_id)
            ).scalar_one()
            if days is None:
                return []
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            ids = list(
                connection.execute(
                    select(tables.documents.c.id).where(
                        tables.documents.c.organization_id == self.organization_id,
                        tables.documents.c.uploaded_at < cutoff,
                    )
                ).scalars()
            )
            if apply:
                for document_id in ids:
                    self._delete_document(connection, document_id)
            return ids

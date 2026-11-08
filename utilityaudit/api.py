"""Authenticated FastAPI adapter. Run with uvicorn utilityaudit.api:create_app --factory."""

import json
import logging
import os
import time
from dataclasses import asdict
from typing import Annotated, Literal
from urllib.parse import quote, urlparse
from uuid import uuid4

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from utilityaudit.auth import SESSION_SECONDS, Auth, Identity
from utilityaudit.database import Database, runtime_database
from utilityaudit.errors import AccessDenied, AuthenticationError, Conflict, DataIntegrityError, NotFound
from utilityaudit.ingestion import MAX_BYTES, IngestionError
from utilityaudit.models import AuditConfig, bill_to_json, json_default, mask_account
from utilityaudit.storage import DuplicateDocumentError, Repository

logger = logging.getLogger("utilityaudit.requests")


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Input):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class Organization(Input):
    name: str = Field(min_length=1, max_length=120)


class Membership(Input):
    role: Literal["owner", "auditor", "viewer"] | None


class Correction(Input):
    expected_version: int = Field(ge=1)
    changes: dict[str, str] = Field(default_factory=dict, max_length=50)
    verified_fields: list[str] = Field(default_factory=list, max_length=50)
    reason: str = Field(min_length=10, max_length=2000)
    source_page: int | None = Field(default=None, ge=1, le=100)


class Review(Input):
    status: Literal["unresolved", "verified", "dismissed"]
    note: str = Field(min_length=10, max_length=2000)
    expected_version: int = Field(ge=0)


class AuditSelection(Input):
    bill_ids: list[str] | None = Field(default=None, max_length=500)


class Thresholds(Input):
    bill_increase_pct: float = Field(default=30, gt=0, le=1000)
    usage_change_pct: float = Field(default=30, gt=0, le=1000)
    rate_change_pct: float = Field(default=20, gt=0, le=1000)
    min_history: int = Field(default=3, ge=3, le=24)
    arithmetic_tolerance: str = Field(default="0.02", max_length=20)
    baseline_mode: Literal["recent", "same_month"] = "recent"


class Retention(Input):
    days: int | None = Field(default=None, ge=1, le=3650)


class PasswordChange(Input):
    old_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = MAX_BYTES + 65536
        headers = dict(scope.get("headers", []))
        length = headers.get(b"content-length", b"")
        if length and (not length.isdigit() or int(length) > limit):
            await JSONResponse({"detail": "Request exceeds upload limits."}, status_code=413)(scope, receive, send)
            return
        received = 0

        async def bounded_receive():
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > limit:
                raise HTTPException(413, "Request exceeds upload limits.")
            return message

        await self.app(scope, bounded_receive, send)


def public_bill(bill) -> dict:
    value = json.loads(bill_to_json(bill))
    value["account_number"] = mask_account(bill.account_number)
    for name in ("invoice_number", "supersedes_invoice_number"):
        value[name] = "Present (see source)" if value[name] else None
    value["provenance"] = {
        name: [{key: value for key, value in source.items() if key != "text"} for source in sources]
        for name, sources in bill.provenance.items()
    }
    return value


def create_app(database: Database | None = None) -> FastAPI:
    db = database or runtime_database()
    auth = Auth(db)
    server_mode = os.environ.get("UTILITYAUDIT_MODE", "local") == "server"
    app = FastAPI(
        title="UtilityAudit AI",
        version="0.2.0",
        docs_url=None if server_mode else "/docs",
        redoc_url=None,
        openapi_url=None if server_mode else "/openapi.json",
    )
    app.state.database = db
    hosts = ["127.0.0.1", "localhost"]
    if database is not None:
        hosts.append("testserver")
    if server_mode:
        hosts.append(urlparse(os.environ["UTILITYAUDIT_PUBLIC_URL"]).hostname)
        app.add_middleware(HTTPSRedirectMiddleware)
    app.add_middleware(BodyLimit)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
    bearer = HTTPBearer(auto_error=False)

    def identity(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]) -> Identity:
        if credentials is None or credentials.scheme.casefold() != "bearer":
            raise AuthenticationError("A bearer session is required.")
        return auth.authenticate(credentials.credentials)

    def repository(organization_id: str, user: Annotated[Identity, Depends(identity)]) -> Repository:
        return Repository(db, user, organization_id)

    Repo = Annotated[Repository, Depends(repository)]
    User = Annotated[Identity, Depends(identity)]

    @app.middleware("http")
    async def request_metadata(request: Request, call_next):
        request_id, start = str(uuid4()), time.monotonic()
        response = await call_next(request)
        response.headers.update(
            {
                "X-Request-ID": request_id,
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            }
        )
        route = request.scope.get("route")
        logger.info(
            json.dumps(
                {
                    "request_id": request_id,
                    "method": request.method,
                    "route": getattr(route, "path", "unmatched"),
                    "status": response.status_code,
                    "duration_ms": round((time.monotonic() - start) * 1000, 2),
                }
            )
        )
        return response

    async def safe_error(request: Request, exc: Exception):
        codes = {
            AccessDenied: 403,
            AuthenticationError: 401,
            Conflict: 409,
            NotFound: 404,
            IngestionError: 422,
            DuplicateDocumentError: 409,
            ValueError: 422,
        }
        status = codes.get(type(exc), 500)
        if status == 500:
            logging.getLogger("utilityaudit").error("Storage/integrity failure: %s", type(exc).__name__)
            detail = "Data operation failed. Contact the operator; no successful write is implied."
        else:
            detail = str(exc)
        return JSONResponse(
            {"detail": detail}, status_code=status, headers={"WWW-Authenticate": "Bearer"} if status == 401 else None
        )

    for exception in (
        AccessDenied,
        AuthenticationError,
        Conflict,
        NotFound,
        IngestionError,
        DuplicateDocumentError,
        ValueError,
        SQLAlchemyError,
        DataIntegrityError,
    ):
        app.add_exception_handler(exception, safe_error)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse(
            {
                "detail": [
                    {"location": error["loc"], "type": error["type"], "message": error["msg"]} for error in exc.errors()
                ]
            },
            status_code=422,
        )

    @app.get("/health/live")
    def live():
        return {"status": "alive"}

    @app.get("/health/ready")
    def ready():
        try:
            with db.engine.connect() as connection:
                connection.execute(select(1))
        except SQLAlchemyError:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return {"status": "ready"}

    @app.post("/auth/login")
    def login(body: Login, request: Request):
        token = auth.login(body.username, body.password, request.client.host if request.client else "unknown")
        return {"access_token": token, "token_type": "bearer", "expires_in": SESSION_SECONDS}

    @app.post("/auth/logout", status_code=204)
    def logout(user: User, credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)]):
        auth.logout(credentials.credentials)

    @app.put("/auth/password", status_code=204)
    def change_password(body: PasswordChange, user: User):
        auth.change_password(user, body.old_password, body.new_password)

    @app.get("/me")
    def me(user: User):
        return {"username": user.username, "organizations": auth.organizations(user)}

    @app.post("/organizations", status_code=201)
    def create_organization(body: Organization, user: User):
        return {"id": auth.create_organization(user, body.name)}

    @app.put("/organizations/{organization_id}/members/{username}", status_code=204)
    def membership(organization_id: str, username: str, body: Membership, user: User):
        auth.set_membership(user, organization_id, username, body.role)

    @app.get("/organizations/{organization_id}/documents")
    def documents(repo: Repo):
        return repo.documents()

    @app.post("/organizations/{organization_id}/documents", status_code=201)
    async def import_document(repo: Repo, file: Annotated[UploadFile, File()]):
        data = await file.read(MAX_BYTES + 1)
        try:
            count = await run_in_threadpool(repo.import_document, file.filename or "", data)
        finally:
            await file.close()
        return {"bills_imported": count}

    @app.get("/organizations/{organization_id}/documents/{document_id}/original")
    def original(document_id: str, repo: Repo):
        name, data = repo.document_download(document_id)
        media = "application/pdf" if data.startswith(b"%PDF-") else "text/csv"
        return Response(
            data,
            media_type=media,
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}"},
        )

    @app.delete("/organizations/{organization_id}/documents/{document_id}", status_code=204)
    def remove_document(document_id: str, repo: Repo):
        repo.delete_document(document_id)

    @app.get("/organizations/{organization_id}/bills")
    def bills(repo: Repo):
        return [public_bill(bill) for bill in repo.bills()]

    @app.get("/organizations/{organization_id}/bills/{bill_id}/source")
    def source_bill(bill_id: str, repo: Repo):
        with repo.connect("source") as connection:
            bill = repo._get_bill(connection, bill_id)
        return json.loads(bill_to_json(bill))

    @app.patch("/organizations/{organization_id}/bills/{bill_id}")
    def correct(bill_id: str, body: Correction, repo: Repo):
        return public_bill(repo.correct(bill_id, **body.model_dump()))

    @app.get("/organizations/{organization_id}/bills/{bill_id}/revisions")
    def revisions(bill_id: str, repo: Repo):
        return repo.revision_history(bill_id)

    @app.get("/organizations/{organization_id}/bills/{bill_id}/reviews")
    def review_history(bill_id: str, repo: Repo):
        return repo.review_history(bill_id)

    @app.get("/organizations/{organization_id}/analysis")
    def analysis(repo: Repo):
        _, result, _ = repo.analysis()
        value = asdict(result)
        value["findings"] = [{**asdict(item), "key": item.key} for item in result.findings]
        return json.loads(json.dumps(value, default=json_default))

    @app.put("/organizations/{organization_id}/findings/{finding_key}/review", status_code=204)
    def review(finding_key: str, body: Review, repo: Repo):
        repo.review(finding_key, **body.model_dump())

    @app.post("/organizations/{organization_id}/audits", status_code=201)
    def run_audit(body: AuditSelection, repo: Repo):
        return {"id": repo.run_audit(body.bill_ids)}

    @app.get("/organizations/{organization_id}/audits")
    def audits(repo: Repo):
        return repo.recent_runs()

    @app.get("/organizations/{organization_id}/audits/{run_id}/report")
    def report(run_id: str, repo: Repo, format: Literal["pdf", "csv"] = "pdf"):
        data = repo.report(run_id, format)
        return Response(
            data,
            media_type="application/pdf" if format == "pdf" else "text/csv",
            headers={"Content-Disposition": f'attachment; filename="utility-audit-{run_id}.{format}"'},
        )

    @app.get("/organizations/{organization_id}/settings")
    def settings(repo: Repo):
        return asdict(repo.config())

    @app.put("/organizations/{organization_id}/settings", status_code=204)
    def save_settings(body: Thresholds, repo: Repo):
        repo.save_config(AuditConfig(**body.model_dump()))

    @app.put("/organizations/{organization_id}/retention", status_code=204)
    def set_retention(body: Retention, repo: Repo):
        repo.set_retention(body.days)

    @app.get("/organizations/{organization_id}/retention/preview")
    def preview_retention(repo: Repo):
        return {"document_ids": repo.purge_expired()}

    @app.get("/organizations/{organization_id}/activity")
    def activity(repo: Repo):
        return repo.activity()

    return app

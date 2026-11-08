"""Local credential authority, revocable sessions and organization membership."""

import base64
import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError

from utilityaudit.database import (
    Database,
    events,
    login_limits,
    memberships,
    organizations,
    sessions,
    users,
    utc_now,
)
from utilityaudit.errors import AccessDenied, AuthenticationError, Conflict

ROLES = ("owner", "auditor", "viewer")
SESSION_SECONDS = 8 * 60 * 60
IDLE_SECONDS = 30 * 60


@dataclass(frozen=True)
class Identity:
    user_id: str
    username: str


def normalize_username(username: str) -> str:
    value = username.strip().casefold()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,63}", value):
        raise ValueError("Username must be 3-64 ASCII letters, digits, dots, underscores or hyphens.")
    return value


def password_hash(password: str) -> str:
    if not 12 <= len(password) <= 128:
        raise ValueError("Use a password of 12 to 128 characters.")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=3, maxmem=128 * 1024 * 1024)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def password_matches(password: str, encoded: str) -> bool:
    if not 1 <= len(password) <= 128:
        return False
    scheme, salt, expected = encoded.split("$")
    if scheme != "scrypt":
        raise AuthenticationError("Credential format is unsupported; contact the administrator.")
    actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=32768, r=8, p=3, maxmem=128 * 1024 * 1024)
    return hmac.compare_digest(actual, base64.b64decode(expected))


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Auth:
    def __init__(self, database: Database):
        self.db = database

    def has_users(self) -> bool:
        with self.db.engine.connect() as connection:
            return connection.execute(select(users.c.id).limit(1)).first() is not None

    def create_user(self, username: str, password: str) -> Identity:
        """Operator-only entry point: exposed by the CLI, never public signup."""
        identity = Identity(str(uuid4()), normalize_username(username))
        hashed = password_hash(password)
        try:
            with self.db.engine.begin() as connection:
                connection.execute(
                    users.insert().values(
                        id=identity.user_id, username=identity.username, password_hash=hashed, active=True
                    )
                )
        except IntegrityError as exc:
            raise Conflict("Username is unavailable.") from exc
        return identity

    def bootstrap(self, username: str, password: str, organization: str) -> tuple[Identity, str]:
        if not 1 <= len(organization.strip()) <= 120:
            raise ValueError("Organization name must contain 1 to 120 characters.")
        identity = Identity(str(uuid4()), normalize_username(username))
        hashed = password_hash(password)
        organization_id = str(uuid4())
        with self.db.engine.begin() as connection:
            if self.db.engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            else:
                connection.exec_driver_sql("SELECT pg_advisory_xact_lock(73510422)")
            if connection.execute(select(users.c.id).limit(1)).first():
                raise Conflict("An operator already exists. Bootstrap is disabled.")
            connection.execute(
                users.insert().values(
                    id=identity.user_id, username=identity.username, password_hash=hashed, active=True
                )
            )
            connection.execute(
                organizations.insert().values(id=organization_id, name=organization.strip(), created_at=utc_now())
            )
            connection.execute(
                memberships.insert().values(organization_id=organization_id, user_id=identity.user_id, role="owner")
            )
        return identity, organization_id

    def login(self, username: str, password: str, peer: str = "local") -> str:
        normalized = username.strip().casefold()[:256]
        now = int(time.time())
        keys = [token_hash("user:" + normalized), token_hash("peer:" + peer)]
        blocked = False
        with self.db.engine.begin() as connection:
            if self.db.engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            else:
                # Serialize counters, including first attempts for previously unseen names.
                connection.exec_driver_sql("SELECT pg_advisory_xact_lock(73510423)")
            connection.execute(delete(login_limits).where(login_limits.c.window_start < now - 900))
            limits = {
                row["key"]: row
                for row in connection.execute(
                    select(login_limits).where(login_limits.c.key.in_(keys)).with_for_update()
                ).mappings()
            }
            for key, maximum in zip(keys, (5, 50)):
                previous = limits.get(key)
                if previous and previous["attempts"] >= maximum:
                    blocked = True
                if previous:
                    connection.execute(
                        update(login_limits).where(login_limits.c.key == key).values(attempts=previous["attempts"] + 1)
                    )
                else:
                    connection.execute(login_limits.insert().values(key=key, attempts=1, window_start=now))
            row = connection.execute(select(users).where(users.c.username == normalized)).mappings().first()
        if blocked:
            raise AuthenticationError("Sign-in temporarily unavailable. Try again after 15 minutes.")
        # A missing user performs the same scrypt work; there are no default credentials.
        encoded = (
            row["password_hash"]
            if row
            else "scrypt$" + base64.b64encode(bytes(16)).decode() + "$" + base64.b64encode(bytes(64)).decode()
        )
        valid = password_matches(password, encoded)
        if not row or not row["active"] or not valid:
            raise AuthenticationError("Invalid credentials or inactive account.")
        token = secrets.token_urlsafe(32)
        with self.db.engine.begin() as connection:
            if self.db.engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            current = (
                connection.execute(select(users).where(users.c.id == row["id"]).with_for_update()).mappings().one()
            )
            if not current["active"] or current["password_hash"] != row["password_hash"]:
                raise AuthenticationError("Credentials changed during sign-in. Try again.")
            connection.execute(delete(sessions).where(sessions.c.expires_at <= now))
            connection.execute(
                sessions.insert().values(
                    token_hash=token_hash(token), user_id=row["id"], expires_at=now + SESSION_SECONDS, last_seen=now
                )
            )
            connection.execute(delete(login_limits).where(login_limits.c.key == keys[0]))
        return token

    def authenticate(self, token: str) -> Identity:
        if not 32 <= len(token) <= 128:
            raise AuthenticationError("Sign in again.")
        now = int(time.time())
        with self.db.engine.begin() as connection:
            row = (
                connection.execute(
                    select(sessions, users.c.username, users.c.active)
                    .join(users)
                    .where(sessions.c.token_hash == token_hash(token))
                )
                .mappings()
                .first()
            )
            if not row or not row["active"] or row["expires_at"] <= now or row["last_seen"] < now - IDLE_SECONDS:
                raise AuthenticationError("Session expired or revoked. Sign in again.")
            connection.execute(update(sessions).where(sessions.c.token_hash == token_hash(token)).values(last_seen=now))
            return Identity(row["user_id"], row["username"])

    def logout(self, token: str) -> None:
        with self.db.engine.begin() as connection:
            connection.execute(delete(sessions).where(sessions.c.token_hash == token_hash(token)))

    def change_password(self, identity: Identity, old_password: str, new_password: str) -> None:
        hashed = password_hash(new_password)
        with self.db.engine.begin() as connection:
            if self.db.engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            row = (
                connection.execute(select(users).where(users.c.id == identity.user_id).with_for_update())
                .mappings()
                .first()
            )
            if not row or not row["active"] or not password_matches(old_password, row["password_hash"]):
                raise AuthenticationError("Current password is incorrect.")
            connection.execute(update(users).where(users.c.id == identity.user_id).values(password_hash=hashed))
            connection.execute(delete(sessions).where(sessions.c.user_id == identity.user_id))

    def reset_password(self, username: str, new_password: str) -> None:
        """Operator-only recovery; deliberately not exposed by the HTTP API."""
        hashed = password_hash(new_password)
        with self.db.engine.begin() as connection:
            if self.db.engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            row = (
                connection.execute(
                    select(users).where(users.c.username == normalize_username(username)).with_for_update()
                )
                .mappings()
                .first()
            )
            if row is None:
                raise ValueError("User not found.")
            connection.execute(update(users).where(users.c.id == row["id"]).values(password_hash=hashed))
            connection.execute(delete(sessions).where(sessions.c.user_id == row["id"]))
            connection.execute(delete(login_limits).where(login_limits.c.key == token_hash("user:" + row["username"])))
            for organization_id in connection.execute(
                select(memberships.c.organization_id).where(memberships.c.user_id == row["id"])
            ).scalars():
                connection.execute(
                    events.insert().values(
                        id=str(uuid4()),
                        organization_id=organization_id,
                        actor_id=None,
                        action="operator.password_reset",
                        subject_id=row["id"],
                        created_at=utc_now(),
                    )
                )

    def organizations(self, identity: Identity) -> list[dict]:
        with self.db.engine.connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    select(organizations.c.id, organizations.c.name, memberships.c.role)
                    .select_from(organizations)
                    .join(memberships, memberships.c.organization_id == organizations.c.id)
                    .join(users, users.c.id == memberships.c.user_id)
                    .where(memberships.c.user_id == identity.user_id, users.c.active.is_(True))
                    .order_by(organizations.c.name)
                ).mappings()
            ]

    def create_organization(self, identity: Identity, name: str) -> str:
        if not 1 <= len(name.strip()) <= 120:
            raise ValueError("Organization name must contain 1 to 120 characters.")
        organization_id = str(uuid4())
        with self.db.engine.begin() as connection:
            if not connection.execute(
                select(users.c.id).where(users.c.id == identity.user_id, users.c.active.is_(True))
            ).first():
                raise AccessDenied("Active membership is required.")
            connection.execute(
                organizations.insert().values(id=organization_id, name=name.strip(), created_at=utc_now())
            )
            connection.execute(
                memberships.insert().values(organization_id=organization_id, user_id=identity.user_id, role="owner")
            )
        return organization_id

    def set_membership(self, identity: Identity, organization_id: str, username: str, role: str | None) -> None:
        if role is not None and role not in ROLES:
            raise ValueError("Role must be owner, auditor or viewer.")
        with self.db.engine.begin() as connection:
            if self.db.engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            self.db.lock_organization(connection, organization_id)
            current_role = connection.execute(
                select(memberships.c.role)
                .join(users)
                .where(
                    memberships.c.organization_id == organization_id,
                    memberships.c.user_id == identity.user_id,
                    users.c.active.is_(True),
                )
            ).scalar_one_or_none()
            if current_role != "owner":
                raise AccessDenied("Only an organization owner can manage membership.")
            target = connection.execute(
                select(users.c.id).where(users.c.username == normalize_username(username))
            ).scalar_one_or_none()
            if target is None:
                raise ValueError("User unavailable. An operator must create the user first.")
            existing = connection.execute(
                select(memberships.c.role).where(
                    memberships.c.organization_id == organization_id, memberships.c.user_id == target
                )
            ).scalar_one_or_none()
            owners = connection.execute(
                select(func.count())
                .select_from(memberships)
                .where(memberships.c.organization_id == organization_id, memberships.c.role == "owner")
            ).scalar_one()
            if existing == "owner" and role != "owner" and owners <= 1:
                raise Conflict("An organization must retain at least one owner.")
            connection.execute(
                delete(memberships).where(
                    memberships.c.organization_id == organization_id, memberships.c.user_id == target
                )
            )
            if role:
                connection.execute(
                    memberships.insert().values(organization_id=organization_id, user_id=target, role=role)
                )
            connection.execute(
                events.insert().values(
                    id=str(uuid4()),
                    organization_id=organization_id,
                    actor_id=identity.user_id,
                    action=f"membership:{role or 'removed'}",
                    subject_id=target,
                    created_at=utc_now(),
                )
            )

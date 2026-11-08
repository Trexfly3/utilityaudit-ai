# Operations and recovery

## Before any public deployment

The code supplies authentication and tenant-scoped operations, not a completed
external security assessment. Operate locally or with a controlled pilot until
the release gates below are satisfied.

Set `UTILITYAUDIT_MODE=server`, an HTTPS `UTILITYAUDIT_PUBLIC_URL`,
`UTILITYAUDIT_DATABASE_URL` using PostgreSQL `sslmode=verify-full` and an appropriate
CA, and `UTILITYAUDIT_ENCRYPTION_KEYS` from your secret manager. Server mode fails
closed without these. Keys are comma-separated Fernet keys, newest first. Never
put real keys, database URLs with passwords, documents or backups in source control.

Use a private PostgreSQL network and a dedicated least-privilege application role.
Schema migrations may need a separate operator identity. The application scopes
queries, but does not yet configure PostgreSQL row-level-security policies.
Do not grant end users direct database access.

Terminate TLS at a controlled reverse proxy. Restrict its upload limit, rate-limit
authentication, and bind application ports to loopback/private networking.
`utilityaudit serve-api` binds only to loopback. `UTILITYAUDIT_TRUSTED_PROXIES`
must contain only actual proxy addresses, never `*`; otherwise client-controlled
forwarded headers can undermine origin/HTTPS handling. Streamlit must be behind
the same access-controlled TLS infrastructure with WebSocket support.

Keep `/docs` and OpenAPI disabled in server mode, as the API does by default.
Store opaque sessions only in a secure client context. The API uses bearer tokens,
not ambient cookies; do not introduce browser cookies without CSRF protections.
Streamlit session tokens stay in server-side session state and clear on logout.

Add platform-specific alerting for login throttles, HTTP 5xx, latency, disk usage,
database health and overdue backup/restore drills. Request logs include a random
request ID, route template, status and duration, never tokens or bill bodies.
`/health/live` checks the process; `/health/ready` checks database connectivity.
They do not certify data accuracy, key recoverability or capacity.

## Database migrations and v1 import

The v2 adapter has a version table and serialized transactional schema creation
for SQLite/PostgreSQL. Unsupported versions fail rather than being silently
modified. Run `utilityaudit migrate` using the intended release and database.
Future structural changes must add explicit versioned migration steps.

The original `data/utilityaudit.sqlite3` is never automatically assigned to a
tenant or overwritten. After bootstrapping an owner and making a backup:

```bash
utilityaudit import-legacy \
  --source data/utilityaudit.sqlite3 \
  --username YOUR_USERNAME \
  --organization-id YOUR_ORGANIZATION_ID
```

The command prompts for the owner's password. Import is transactional, retains
original documents and parsed fields, creates new local references, and labels
missing legacy provenance honestly. Duplicate source files abort rather than
silently creating copies. The legacy file remains unchanged and may still contain
plaintext sensitive information: restrict it, retain it according to your policy,
and retire it only after verification and approved backup handling.

Do not run two schema-changing releases simultaneously. Take a verified backup
before migration; rollback means restoring a separately verified backup to a new
target, not downgrading an unknown schema in place.

## Backups and recovery

```bash
utilityaudit backup --output backups/audit-YYYYMMDD.sqlite3
utilityaudit verify-data
```

The command uses SQLite's online backup API or PostgreSQL's custom `pg_dump`
format. PostgreSQL requires compatible `pg_dump`/`pg_restore` executables.
Run PostgreSQL backup/restore commands on an operator host with those clients;
they are not bundled in the UI container image.
Outputs and checksum manifests are private files. Keys are **not included**.
The SHA-256 manifest detects accidental corruption, not an attacker who can
replace both files. Encrypted payload authentication additionally detects
tampering and cross-record substitution.

Back up encryption keys separately under appropriate custody. A database backup
without its keys cannot recover encrypted content. Maintain an offline copy and
test key access through the same procedure your incident operator will use.

Restore SQLite to a **new path**:

```bash
utilityaudit restore-sqlite --backup backups/audit-YYYYMMDD.sqlite3 \
  --output recovery/utilityaudit-v2.sqlite3
```

Point `UTILITYAUDIT_DATA_DIR` at the directory containing the original key, or
supply keys through the environment/secret manager before restoring. Existing
output files are never overwritten.

Restore PostgreSQL into a separately provisioned **empty database** by setting
`UTILITYAUDIT_RESTORE_DATABASE_URL` privately:

```bash
utilityaudit restore-postgres --backup backups/audit-YYYYMMDD.dump
```

Restore checks the manifest, verifies encrypted payloads, and revokes copied
sessions. Test sign-in, document reads, correction history and saved PDF/CSV
downloads before switching application traffic. Record actual restore time and
choose recovery-time/recovery-point objectives with the customer; none are claimed
by this code. A failed verification must not be used as a live database.

## Key rotation

1. Stop all application writers and take a verified backup with the old key.
2. Supply `UTILITYAUDIT_ENCRYPTION_KEYS` with the new key first and old keys after it.
3. Run `utilityaudit rotate-keys --offline-confirm`, then `utilityaudit verify-data`.
4. Verify a restore and application reads with only the new key before retiring
   old active keys. Historical backups still require their historical keys.
5. Restart every writer with the new key. Leaving an old writer running can
   reintroduce old-key ciphertext.

Rotation changes encryption, not audit-record meaning. Host compromise is not
solved by simply rotating a key on the same compromised host.

## Operator-assisted account recovery

After verifying the person's identity through your organization's recovery
procedure, a trusted database operator can run
`utilityaudit user-reset --username THEIR_USERNAME`. The password is prompted
privately, all of that user's sessions are revoked, and each affected organization
receives an `operator.password_reset` event (not falsely attributed to the user).
This command is not exposed by the web API. It does not automate identity proof,
email delivery, MFA recovery or the customer's approval policy.

## Retention and deletion

An owner sets retention days from Settings or the API. No automatic destructive
job is enabled. Preview and explicitly apply:

```bash
utilityaudit purge-expired --username YOUR_USERNAME --organization-id YOUR_ORGANIZATION_ID
utilityaudit purge-expired --username YOUR_USERNAME --organization-id YOUR_ORGANIZATION_ID --apply
```

Purging removes expired originals, bill payloads, sensitive correction/review
history, and the contents of report snapshots that depended on those bills.
Minimal non-content event metadata and purged run counts remain. Removal is not
a promise of forensic erasure on storage or deletion from external backups.
Set a separate backup retention policy and document legal holds before scheduling
the operator command in your controlled infrastructure.

## Release gates still requiring outside work

Independent security review/penetration testing; isolated untrusted-document
processing; SSO/MFA and account recovery
policy; hosting/network/TLS/secrets setup; tested operational alerting and backup
cadence; applicable privacy/retention agreements; provider-specific accuracy
evidence; commercial dependency licensing. Do not equate passing local tests with
these approvals.

# UtilityAudit AI

An evidence-based utility-bill auditing application with a Streamlit dashboard,
an authenticated FastAPI API, encrypted SQLite/PostgreSQL persistence, and a
framework-independent deterministic engine. No paid APIs, external AI, telemetry
service, or network-based invoice processing.

**This is a pilot foundation, not a certified financial system.** The shipped
ground truth is synthetic. Real-provider accuracy, human audit outcomes, public
deployment security and commercial licensing still need independent validation.

## Run locally

Python 3.11 or 3.12:

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install --no-deps -e .
.venv/bin/utilityaudit bootstrap --username YOUR_USERNAME --organization "YOUR ORGANIZATION"
.venv/bin/streamlit run app.py
```

Bootstrap privately prompts for a 12-128 character password. There are **no default
credentials and no public signup**. Bootstrap is disabled after the first user
exists. Open http://127.0.0.1:8501 and sign in. Download the synthetic CSV example
on Upload Bills or use `samples/bills.csv`. Test documents are not automatically
loaded into your organization.

To run the API separately:

```bash
.venv/bin/utilityaudit serve-api --port 8000
```

Local OpenAPI documentation: http://127.0.0.1:8000/docs. Authenticate with
`POST /auth/login`; send the returned opaque token as `Authorization: Bearer ...`.
Keep tokens out of URLs, shell history, source files and logs.

## What's implemented

- Six dashboard pages, multi-document PDF/CSV uploads, masked history, original
  document viewing, deletion, charts and persistent settings.
- Field-level source page/CSV row evidence. Human corrections retain original
  evidence, append a versioned before/after record, and reject stale edits.
- Unresolved/verified/dismissed finding decisions with required evidence notes,
  reviewer identity and append-only decision history. Any analysis input/config
  change invalidates prior decisions for the current result. A human-verified
  finding is **not** a confirmed overcharge or recovery.
- Deterministic duplicate invoice/charge, amount/usage/rate change, arithmetic,
  billing-overlap and missing-information checks, plus balance reconciliation.
  Every rule exposes whether it checked, flagged or skipped a bill and why.
- Service/meter-scoped comparisons, explicitly linked replacements, credit-note
  exclusions and optional same-calendar-month historical baselines.
- Immutable PDF/CSV snapshot bytes, including calculations, rule coverage,
  versioned inputs, thresholds, review status and verification caveats. Snapshots
  don't change after corrections. Deleting source data purges dependent report
  contents rather than retaining hidden copies.
- Password hashing, throttled sign-in, expiring/revocable sessions, organization
  membership and owner/auditor/viewer roles enforced in repository operations.
- Encrypted document contents/names, bills, settings, revisions, reviews and
  snapshots. Ciphertexts are authenticated against tenant/record context.
- Versioned schema initialization, explicit v1 migration, key rotation,
  backup/restore verification, retention previews and an operator purge command.

## Architecture

| Module | Responsibility |
|---|---|
| `models`, `audit` | Domain types, exact calculations, evidence and coverage |
| `ingestion` | Bounded PDF/CSV parsing, provenance and correction validation |
| `history`, `reports` | Aggregates and standalone exports |
| `database`, `crypto`, `storage` | Versioned SQLAlchemy schema, encryption, tenant-scoped transactions |
| `auth` | Credentials, sessions and roles |
| `api`, `app.py` | FastAPI and Streamlit adapters sharing the same services |
| `operations`, `cli` | Recovery, legacy migration, retention and key operations |
| `evaluation` | Local permissioned/synthetic ground-truth evaluation |

SQLite remains the default. Use `UTILITYAUDIT_DATABASE_URL` with
`postgresql+psycopg://...` for PostgreSQL. All organization reads and writes are
scoped and permission-checked. PostgreSQL row-level security is **not** implemented;
database credentials are privileged and must never be exposed to clients.

## Storage, users and roles

Default data directory: `data/`, overridden with `UTILITYAUDIT_DATA_DIR`.
The new database is `utilityaudit-v2.sqlite3`. Local mode creates
`encryption.key` with mode 0600; the directory is private. Keeping the key on the
same host protects a database-only copy, **not a compromised host**. Back up the
key separately. Server mode requires externally supplied keys and verified
PostgreSQL TLS; see [operations](docs/OPERATIONS.md).

Usernames, organization names, memberships, timestamps and non-content audit
events remain database metadata. Passwords are stored as salted scrypt hashes.
Sessions are random opaque tokens stored only as hashes, with an eight-hour
absolute lifetime and 30-minute idle timeout. Logout/password change revokes
sessions. Five attempts per username or 50 per peer in 15 minutes throttle login.
Streamlit uses a shared local peer bucket; configure upstream request limits for
public deployments.

Owners manage membership/settings/retention and delete documents. Auditors
upload, inspect sources, correct, review and generate snapshots. Viewers see
masked bill views, analysis and saved reports, but cannot fetch originals or
edit data. Customer names and financial amounts remain sensitive in all reports.

An operator creates additional users with `utilityaudit user-add --username ...`.
An owner assigns their existing username a role from Settings or the API.
Operator-assisted recovery uses `utilityaudit user-reset --username ...`, with
a private password prompt, session revocation and an explicit operator event.
Removing membership takes effect on subsequent operations. Logout and organization
switching clear sensitive frontend workspace state.

## CSV contract

UTF-8; one invoice per row; snake_case headers; ISO dates (`YYYY-MM-DD`); decimal
numbers without thousands separators. `total_due` is a required header, but its
cells may be blank. Empty cells stay missing; identifiers retain leading zeros.
Unknown headers and invalid rows reject the entire document.

Supported columns:

```
provider,account_number,customer_name,invoice_number,currency,utility_type,
service_id,meter_id,invoice_kind,supersedes_invoice_number,
period_start,period_end,invoice_date,due_date,
electricity_kwh,gas_therms,water_usage,water_unit,
base_charges,delivery_charges,energy_charges,taxes,additional_fees,
total_due,total_basis,current_charges,previous_balance,payments,credits,
line_items_complete,line_items
```

`currency` is an explicit three-letter code; currencies are never converted or
combined. `utility_type` is electricity/gas/water/mixed. `total_basis` is
current_charges/amount_due. Unknown currencies are excluded from monetary sums.

For `amount_due`, balance reconciliation requires **all** of
`current_charges + previous_balance - payments - credits`. Payments and credits
are nonnegative reductions; prior balances and charge items may be signed.
These balance credits must not also be subtracted from current charges.
Current-charge history never treats carried balances as new spending.

`invoice_kind` is original/replacement/credit. A replacement must explicitly
reference one older invoice, with the same account/service/meter, currency and
period and a later invoice date. Ambiguous replacement relationships are
excluded and require human review. Credit notes are excluded from trend totals:
reconcile them through the receiving invoice's balance credits to avoid double
counting. Nothing is silently converted into a negative amount.

`line_items` is a JSON array with `description`, `amount`, `category` and optional
`service_reference`. `line_items_complete=true` declares those items exhaustive.
Without explicit items, all five charge categories must be populated to declare
completeness. Items take precedence over category totals; they are never added
together. Matching service references matter for duplicate-charge checks.

## PDF contract and limits

PDF interpretation is conservative and label-based. It is **not general-purpose
OCR or provider-layout understanding**. Supported labels include:

```
Utility Provider: ...
Account Number: ...
Billing Period: 2026-01-01 to 2026-01-31
Invoice Date: 2026-01-31
Electricity Usage: 1000 kWh
Total Amount Due: 123.45
Currency: USD
```

Separate start/end labels, charge categories, current charges, balance fields,
meter/service IDs and explicit replacement labels are supported. Units must be
explicit. Conflicting/ambiguous values stay uncertain. US numeric dates are only
accepted when unambiguous. PDF category totals are never presumed exhaustive.
Each labeled field retains its page and source line. PDF corrections require a
valid source-page citation.

Image-only/password-protected/unreadable PDFs are rejected with guidance to
provide readable text or structured CSV. Limits: 10 MiB/file, 100 PDF pages,
2 million extracted characters, 5,000 CSV rows and 1,000 items/invoice. UI batches
are limited to 20 files/50 MiB; API uploads are one file per request with bounded
multipart bodies. This release caps organizations at 5,000 active bills and
report snapshots at 500 selected bills. These are explicit safety limits, not
enterprise capacity claims.

## Interpretation and known limitations

- A mathematical discrepancy establishes inconsistent supplied numbers, not a
  provider error. Missing fields are never fabricated or treated as zero.
- Historical thresholds use exact rational comparisons and daily normalization.
  Recent mode requires at least three earlier non-overlapping bills. Same-month
  mode requires bills from at least three earlier years in that calendar month,
  using the last eligible bill per year. Neither mode models weather or occupancy.
- Effective electricity price is explicit electricity-only base + delivery +
  energy charges divided by kWh. It excludes taxes/fees and is not a tariff rate.
- Monthly charts assign bills to invoice month (period-end fallback). They are
  not calendar-month prorated usage. Coverage counts identify partial aggregates.
- Estimates use the largest positive candidate amount per bill. Dismissed
  findings are excluded, but verified findings are still not recovered savings.
- Append-only change/review history is application-enforced, not a cryptographic
  ledger against a database administrator. Source deletion/retention deliberately
  removes related sensitive records. Backups have their own retention obligations.
- Green Button/XML, tariff databases, OCR, subscriptions, automated disputes,
  SSO/MFA and automated email invitations are not implemented.

## Validation and release checks

```bash
.venv/bin/pytest -q -m 'not postgres'
.venv/bin/ruff check utilityaudit app.py tests
.venv/bin/ruff format --check utilityaudit app.py tests
.venv/bin/utilityaudit evaluate samples/ground_truth.json
.venv/bin/pip check
```

The PostgreSQL test requires a **disposable admin database** in
`UTILITYAUDIT_TEST_POSTGRES_URL` and matching `pg_dump`/`pg_restore` clients. It
creates and drops only uniquely named test databases, and exercises encrypted
backup recovery on an actual PostgreSQL server. Run with `pytest -q -m postgres`.
The GitHub Actions workflow checks SQLite and PostgreSQL on Python 3.11/3.12
for pushes and pull requests.

`requirements.lock` pins the validated runtime and test environment. Review
dependency updates and regenerate the lock after testing. The included Dockerfile
is a non-root local/pilot image; publish the port only on loopback and persist
`/app/data`. It includes validation tools, not a minimal hardened production image.

See [operations and recovery](docs/OPERATIONS.md) and
[accuracy evaluation and pilot requirements](docs/VALIDATION.md).

**Commercial licensing gate:** PyMuPDF has AGPL/commercial licensing obligations.
Run `utilityaudit licenses` for an installed dependency inventory. Obtain a
qualified license review before distributing or offering a proprietary hosted
product; the inventory is not legal clearance.

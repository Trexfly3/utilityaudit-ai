"""Domain types shared by ingestion, storage, analysis and presentation."""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import uuid4

IDENTITY_FIELDS = ("provider", "account_number", "customer_name", "invoice_number")
DATE_FIELDS = ("period_start", "period_end", "invoice_date", "due_date")
NUMBER_FIELDS = (
    "electricity_kwh",
    "gas_therms",
    "water_usage",
    "base_charges",
    "delivery_charges",
    "energy_charges",
    "taxes",
    "additional_fees",
    "total_due",
    "current_charges",
    "previous_balance",
    "payments",
    "credits",
)
TEXT_FIELDS = IDENTITY_FIELDS + (
    "currency",
    "water_unit",
    "total_basis",
    "utility_type",
    "service_id",
    "meter_id",
    "invoice_kind",
    "supersedes_invoice_number",
)
EXTRACTED_FIELDS = TEXT_FIELDS + DATE_FIELDS + NUMBER_FIELDS
CHARGE_FIELDS = ("base_charges", "delivery_charges", "energy_charges", "taxes", "additional_fees")
RULE_VERSION = "2.0"


@dataclass
class LineItem:
    description: str
    amount: Decimal
    category: str
    service_reference: str | None = None


@dataclass
class Bill:
    id: str = field(default_factory=lambda: str(uuid4()))
    document_id: str = ""
    source_row: int | None = None
    version: int = 1
    provider: str | None = None
    account_number: str | None = None
    customer_name: str | None = None
    invoice_number: str | None = None
    currency: str | None = None
    water_unit: str | None = None
    total_basis: str | None = None
    utility_type: str | None = None
    service_id: str | None = None
    meter_id: str | None = None
    invoice_kind: str | None = None
    supersedes_invoice_number: str | None = None
    period_start: date | None = None
    period_end: date | None = None
    invoice_date: date | None = None
    due_date: date | None = None
    electricity_kwh: Decimal | None = None
    gas_therms: Decimal | None = None
    water_usage: Decimal | None = None
    base_charges: Decimal | None = None
    delivery_charges: Decimal | None = None
    energy_charges: Decimal | None = None
    taxes: Decimal | None = None
    additional_fees: Decimal | None = None
    total_due: Decimal | None = None
    current_charges: Decimal | None = None
    previous_balance: Decimal | None = None
    payments: Decimal | None = None
    credits: Decimal | None = None
    line_items: list[LineItem] = field(default_factory=list)
    line_items_complete: bool = False
    quality: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    provenance: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def reliable(self, *names: str) -> bool:
        return all(
            getattr(self, name) is not None and self.quality.get(name) in ("extracted", "verified") for name in names
        )

    @property
    def days(self) -> int | None:
        if self.period_start and self.period_end:
            return (self.period_end - self.period_start).days + 1
        return None

    @property
    def reference(self) -> str:
        # Invoice numbers can themselves contain account identifiers.
        return f"Bill {self.id[:8]}" + (f" / row {self.source_row}" if self.source_row else "")


@dataclass
class Finding:
    code: str
    bill_id: str
    reference: str
    description: str
    severity: str
    classification: str
    evidence: dict[str, Any]
    explanation: str
    recommendation: str
    confidence: str = "medium"
    verification: str = "Human verification required"
    estimated_impact: Decimal | None = None
    related_bill_ids: list[str] = field(default_factory=list)
    input_digest: str = ""
    review_status: str = "unresolved"
    review_note: str = ""
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    review_version: int = 0

    @property
    def key(self) -> str:
        identity = [RULE_VERSION, self.input_digest, self.bill_id, self.code, self.evidence, self.related_bill_ids]
        return hashlib.sha256(json.dumps(identity, default=json_default, sort_keys=True).encode()).hexdigest()


@dataclass
class CheckCoverage:
    bill_id: str
    reference: str
    check: str
    status: str
    reason: str
    metric: str | None = None


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)
    coverage: list[CheckCoverage] = field(default_factory=list)
    exclusions: dict[str, str] = field(default_factory=dict)
    input_digest: str = ""


@dataclass
class AuditConfig:
    bill_increase_pct: float = 30
    usage_change_pct: float = 30
    rate_change_pct: float = 20
    min_history: int = 3
    arithmetic_tolerance: str = "0.02"
    baseline_mode: str = "recent"

    def __post_init__(self) -> None:
        for value in (self.bill_increase_pct, self.usage_change_pct, self.rate_change_pct):
            if type(value) not in (int, float) or not 0 < value <= 1000:
                raise ValueError("Percentage thresholds must be between 0 and 1000.")
        if not isinstance(self.min_history, int) or not 3 <= self.min_history <= 24:
            raise ValueError("Historical baseline must contain 3 to 24 bills.")
        try:
            tolerance = Decimal(self.arithmetic_tolerance)
        except (InvalidOperation, TypeError) as exc:
            raise ValueError("Arithmetic tolerance must be a decimal number.") from exc
        if not tolerance.is_finite() or not 0 <= tolerance <= 1:
            raise ValueError("Arithmetic tolerance must be between 0 and 1.")
        if self.baseline_mode not in ("recent", "same_month"):
            raise ValueError("Baseline mode must be recent or same_month.")


def json_default(value: Any) -> str:
    if isinstance(value, (Decimal, date)):
        return str(value)
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def bill_to_json(bill: Bill) -> str:
    return json.dumps(asdict(bill), default=json_default)


def bill_from_json(payload: str) -> Bill:
    data = json.loads(payload)
    for name in DATE_FIELDS:
        data[name] = date.fromisoformat(data[name]) if data.get(name) is not None else None
    for name in NUMBER_FIELDS:
        data[name] = Decimal(data[name]) if data.get(name) is not None else None
    data["line_items"] = [
        LineItem(item["description"], Decimal(item["amount"]), item["category"], item.get("service_reference"))
        for item in data["line_items"]
    ]
    return Bill(**data)


def mask_account(value: str | None) -> str:
    return "Not available" if not value else "****" + (value[-4:] if len(value) > 4 else "")

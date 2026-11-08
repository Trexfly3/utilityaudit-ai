"""Strict structured imports and conservative, label-based PDF extraction."""

import csv
import hashlib
import io
import json
import re
from copy import deepcopy
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path
from uuid import uuid4

import pandas as pd
import pymupdf as fitz

from utilityaudit.models import (
    CHARGE_FIELDS,
    DATE_FIELDS,
    EXTRACTED_FIELDS,
    NUMBER_FIELDS,
    Bill,
    LineItem,
)

MAX_BYTES = 10 * 1024 * 1024
MAX_ROWS = 5000


class IngestionError(ValueError):
    """Actionable import error safe to display without exposing bill contents."""


def parse_number(value: str) -> Decimal:
    if not re.fullmatch(r"-?\d+(?:\.\d{1,8})?", value):
        raise ValueError("use a plain decimal number with up to 8 decimal places")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("invalid decimal number") from exc
    if not result.is_finite() or abs(result) > Decimal("1000000000000"):
        raise ValueError("number is outside the supported range")
    return result


def parse_date(value: str, pdf: bool = False) -> date:
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return date.fromisoformat(value)
    if pdf and re.fullmatch(r"\d{1,2}/\d{1,2}/\d{4}", value):
        month, day, year = map(int, value.split("/"))
        if month <= 12 and day <= 12 and month != day:
            raise ValueError("ambiguous numeric date; use ISO YYYY-MM-DD")
        return date(year, month, day)
    raise ValueError("use ISO YYYY-MM-DD dates")


def set_field(bill: Bill, name: str, value: str, pdf: bool = False) -> None:
    if not value.strip():
        return
    value = value.strip()
    if name in NUMBER_FIELDS:
        if pdf:
            value = re.sub(r"^[$£€]\s*", "", value)
            unit = {"electricity_kwh": "kWh", "gas_therms": "therms"}.get(name)
            if unit:
                value = re.sub(rf"\s*{unit}$", "", value, flags=re.IGNORECASE)
            if re.fullmatch(r"-?\d{1,3}(?:,\d{3})+(?:\.\d+)?", value):
                value = value.replace(",", "")
        parsed = parse_number(value)
        if name in ("electricity_kwh", "gas_therms", "water_usage", "payments", "credits") and parsed < 0:
            raise ValueError("usage, payments and credits must be nonnegative")
        setattr(bill, name, parsed)
    elif name in DATE_FIELDS:
        setattr(bill, name, parse_date(value, pdf=pdf))
    else:
        if len(value) > 250:
            raise ValueError("text field exceeds 250 characters")
        if name == "currency":
            value = value.upper()
            if not re.fullmatch(r"[A-Z]{3}", value):
                raise ValueError("currency must be a three-letter code")
        if name == "total_basis" and value not in ("amount_due", "current_charges"):
            raise ValueError("total_basis must be amount_due or current_charges")
        if name == "utility_type" and value not in ("electricity", "gas", "water", "mixed"):
            raise ValueError("utility_type must be electricity, gas, water or mixed")
        if name == "invoice_kind" and value not in ("original", "replacement", "credit"):
            raise ValueError("invoice_kind must be original, replacement or credit")
        setattr(bill, name, value)
    bill.quality[name] = "extracted"


def finalize(bill: Bill, strict: bool) -> Bill:
    if bill.period_start and bill.period_end and bill.period_end < bill.period_start:
        if strict:
            raise ValueError("period_end precedes period_start")
        bill.quality["period_start"] = bill.quality["period_end"] = "uncertain"
        bill.warnings.append("Billing period is reversed; excluded from date calculations.")
    if bill.invoice_date and bill.due_date and bill.due_date < bill.invoice_date:
        if strict:
            raise ValueError("due_date precedes invoice_date")
        bill.quality["due_date"] = "uncertain"
        bill.warnings.append("Due date precedes invoice date; verify against the document.")
    for name in EXTRACTED_FIELDS:
        bill.quality.setdefault(name, "missing")
    return bill


def parse_items(value: str) -> list[LineItem]:
    try:
        items = json.loads(value)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("line_items must be a shallow JSON array") from exc
    if not isinstance(items, list) or len(items) > 1000:
        raise ValueError("line_items must contain at most 1000 items")
    result = []
    for item in items:
        required = {"description", "amount", "category"}
        if not isinstance(item, dict) or not required <= set(item) or set(item) - required - {"service_reference"}:
            raise ValueError("each item requires description, amount and category; service_reference is optional")
        for key in ("description", "category", "service_reference"):
            label = item.get(key)
            if key == "service_reference" and label is None:
                continue
            if not isinstance(label, str) or not label.strip() or len(label) > 250:
                raise ValueError("item labels must be nonempty strings up to 250 characters")
        result.append(
            LineItem(
                item["description"].strip(),
                parse_number(str(item["amount"])),
                item["category"].strip(),
                item.get("service_reference"),
            )
        )
    return result


def validate_complete_items(bill: Bill) -> None:
    if bill.line_items_complete and not bill.line_items and not all(bill.reliable(name) for name in CHARGE_FIELDS):
        raise ValueError("complete items require explicit line_items or all five reliable charge categories")


def correct_bill(bill: Bill, changes: dict[str, str], verified_fields: list[str]) -> Bill:
    allowed = set(EXTRACTED_FIELDS) | {"line_items", "line_items_complete"}
    if set(changes) - allowed or set(verified_fields) - set(EXTRACTED_FIELDS):
        raise ValueError("Unknown or immutable correction field.")
    if not changes and not verified_fields:
        raise ValueError("Supply a correction or a field to verify.")
    result = deepcopy(bill)
    for name, value in changes.items():
        if not isinstance(value, str) or len(value) > 131072:
            raise ValueError("Correction values must be bounded strings.")
        if name == "line_items":
            result.line_items = parse_items(value) if value.strip() else []
        elif name == "line_items_complete":
            if value not in ("true", "false"):
                raise ValueError("line_items_complete must be true or false.")
            result.line_items_complete = value == "true"
        else:
            setattr(result, name, None)
            result.quality[name] = "missing"
            set_field(result, name, value)
            if getattr(result, name) is not None:
                result.quality[name] = "verified"
    for name in verified_fields:
        value = getattr(result, name)
        if value is None:
            raise ValueError("A missing value cannot be verified.")
        set_field(result, name, str(value))
        result.quality[name] = "verified"
    finalize(result, strict=True)
    validate_complete_items(result)
    result.version += 1
    return result


def parse_csv(data: bytes, document_id: str) -> list[Bill]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestionError("CSV must be UTF-8 encoded.") from exc
    if "\x00" in text:
        raise IngestionError("CSV contains invalid null characters.")
    try:
        rows = list(csv.reader(io.StringIO(text.rstrip("\r\n")), strict=True))
    except csv.Error as exc:
        raise IngestionError("Malformed CSV quoting or oversized cell.") from exc
    if len(rows) < 2:
        raise IngestionError("CSV must contain a header and at least one invoice.")
    headers = rows[0]
    allowed = set(EXTRACTED_FIELDS) | {"line_items", "line_items_complete"}
    if len(headers) != len(set(headers)):
        raise IngestionError("CSV contains duplicate headers.")
    if "total_due" not in headers or set(headers) - allowed:
        raise IngestionError("CSV requires total_due and only documented snake_case headers.")
    if len(rows) - 1 > MAX_ROWS:
        raise IngestionError(f"CSV exceeds {MAX_ROWS} invoice rows.")
    if any(len(row) != len(headers) for row in rows[1:]):
        raise IngestionError("Every CSV row must contain the same number of columns as its header.")
    # Construct from validated strings, avoiding numeric inference and lost leading zeros.
    frame = pd.DataFrame(rows[1:], columns=headers, dtype=str)
    bills = []
    for index, row in frame.iterrows():
        bill = Bill(document_id=document_id, source_row=int(index) + 2)
        name = "row"
        try:
            for name in EXTRACTED_FIELDS:
                set_field(bill, name, row.get(name, ""))
                if row.get(name, "").strip():
                    bill.provenance[name] = [{"kind": "csv", "row": bill.source_row, "column": name, "text": row[name]}]
            name = "line_items_complete"
            complete = row.get(name, "").strip().lower()
            if complete not in ("", "false", "true"):
                raise ValueError("use true or false")
            bill.line_items_complete = complete == "true"
            for name in ("line_items", "line_items_complete"):
                if row.get(name, "").strip():
                    bill.provenance[name] = [{"kind": "csv", "row": bill.source_row, "column": name, "text": row[name]}]
            name = "line_items"
            if row.get(name, "").strip():
                bill.line_items = parse_items(row[name])
            validate_complete_items(bill)
            name = "dates"
            finalize(bill, strict=True)
        except (ValueError, TypeError) as exc:
            # Do not echo customer-provided cell values.
            if isinstance(exc, json.JSONDecodeError):
                reason = "invalid JSON array"
            else:
                reason = str(exc) if name != "dates" else "invalid date ordering"
            raise IngestionError(f"CSV row {bill.source_row}, {name}: {reason}.") from exc
        bills.append(bill)
    return bills


PDF_LABELS = {
    "provider": ("Utility Provider", "Provider"),
    "account_number": ("Account Number", "Account No"),
    "customer_name": ("Customer Name",),
    "invoice_number": ("Invoice Number", "Invoice No"),
    "currency": ("Currency",),
    "water_unit": ("Water Unit",),
    "utility_type": ("Utility Type",),
    "total_basis": ("Total Basis",),
    "service_id": ("Service ID",),
    "meter_id": ("Meter ID", "Meter Number"),
    "invoice_kind": ("Invoice Kind",),
    "supersedes_invoice_number": ("Supersedes Invoice Number",),
    "period_start": ("Billing Period Start", "Period Start"),
    "period_end": ("Billing Period End", "Period End"),
    "invoice_date": ("Invoice Date",),
    "due_date": ("Due Date",),
    "electricity_kwh": ("Electricity Usage (kWh)", "kWh"),
    "gas_therms": ("Gas Usage (therms)", "Therms"),
    "water_usage": ("Water Usage",),
    "base_charges": ("Base Charges",),
    "delivery_charges": ("Delivery Charges",),
    "energy_charges": ("Energy Charges",),
    "taxes": ("Taxes",),
    "additional_fees": ("Additional Fees",),
    "total_due": ("Total Amount Due", "Total Due"),
    "current_charges": ("Current Charges",),
    "previous_balance": ("Previous Balance",),
    "payments": ("Payments",),
    "credits": ("Credits",),
}


def label_values(text: str, labels: tuple[str, ...]) -> set[str]:
    alternatives = "|".join(re.escape(label) for label in labels)
    return {
        value.strip()
        for value in re.findall(
            rf"^[ \t]*(?:{alternatives})[ \t]*:[ \t]*([^\n\r]+)", text, flags=re.IGNORECASE | re.MULTILINE
        )
        if value.strip()
    }


def parse_pdf(data: bytes, document_id: str) -> list[Bill]:
    if not data.startswith(b"%PDF-"):
        raise IngestionError("File does not have a valid PDF signature.")
    try:
        with fitz.open(stream=data, filetype="pdf") as document:
            if document.needs_pass:
                raise IngestionError("Password-protected PDF: export an unlocked copy first.")
            if not 1 <= document.page_count <= 100:
                raise IngestionError("PDF must contain between 1 and 100 pages.")
            parts = []
            total = 0
            for page in document:
                part = page.get_text()
                total += len(part)
                if total > 2_000_000:
                    raise IngestionError("PDF extracted text exceeds the supported size.")
                parts.append(part)
            text = "\n".join(parts)
    except IngestionError:
        raise
    except (fitz.FileDataError, RuntimeError, ValueError) as exc:
        raise IngestionError("PDF is malformed or cannot be read. Export a fresh copy.") from exc
    if not text.strip():
        raise IngestionError("No readable PDF text. Scanned bills need OCR; import a structured CSV instead.")
    bill = Bill(document_id=document_id)
    for page_number, part in enumerate(parts, 1):
        for line in part.splitlines():
            if ":" not in line:
                continue
            label = line.split(":", 1)[0].strip().casefold()
            for name, labels in PDF_LABELS.items():
                extra = {
                    "electricity_kwh": ("Electricity Usage",),
                    "gas_therms": ("Gas Usage",),
                    "period_start": ("Billing Period",),
                    "period_end": ("Billing Period",),
                }.get(name, ())
                if label in {item.casefold() for item in labels + extra}:
                    bill.provenance.setdefault(name, []).append(
                        {"kind": "pdf", "page": page_number, "label": label, "text": line[:1000]}
                    )
    for name, labels in PDF_LABELS.items():
        values = label_values(text, labels)
        if name in ("electricity_kwh", "gas_therms"):
            label, unit = ("Electricity Usage", "kWh") if name == "electricity_kwh" else ("Gas Usage", "therms")
            for value in label_values(text, (label,)):
                # Generic usage labels do not establish units (e.g. gas may be CCF).
                if not re.search(rf"{unit}$", value, flags=re.IGNORECASE):
                    value += " (unit not established)"
                values.add(value)
        if not values:
            continue
        if len(values) != 1:
            bill.quality[name] = "uncertain"
            bill.warnings.append(f"Conflicting {name} labels; verify manually.")
            continue
        try:
            set_field(bill, name, values.pop(), pdf=True)
        except ValueError:
            bill.quality[name] = "uncertain"
            bill.warnings.append(f"Could not reliably interpret {name}; use a structured CSV.")
    ranges = label_values(text, ("Billing Period",))
    if ranges:
        date_pattern = r"(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})"
        match = re.fullmatch(rf"{date_pattern}\s+(?:to|-)\s+{date_pattern}", next(iter(ranges)), flags=re.IGNORECASE)
        try:
            if len(ranges) != 1 or match is None:
                raise ValueError("ambiguous billing period")
            start, end = (parse_date(value, pdf=True) for value in match.groups())
            for name, value in (("period_start", start), ("period_end", end)):
                if bill.quality.get(name) == "uncertain" or (
                    getattr(bill, name) is not None and getattr(bill, name) != value
                ):
                    raise ValueError("conflicting billing period")
            bill.period_start, bill.period_end = start, end
            bill.quality["period_start"] = bill.quality["period_end"] = "extracted"
        except ValueError:
            bill.period_start = bill.period_end = None
            bill.quality["period_start"] = bill.quality["period_end"] = "uncertain"
            bill.warnings.append("Billing period is ambiguous or conflicts with other date labels.")
    if not any(bill.quality.get(name) == "extracted" for name in NUMBER_FIELDS):
        bill.warnings.append("No supported numeric labels found. Import structured CSV for useful analysis.")
    bill.warnings.append("PDF category totals are not assumed to be exhaustive line items.")
    return [finalize(bill, strict=False)]


def ingest(filename: str, data: bytes) -> tuple[str, str, list[Bill]]:
    if not data or len(data) > MAX_BYTES:
        raise IngestionError("Upload a nonempty file no larger than 10 MiB.")
    extension = Path(filename).suffix.lower()
    if extension not in (".pdf", ".csv"):
        raise IngestionError("Only PDF and CSV files are supported.")
    document_id = str(uuid4())
    bills = parse_pdf(data, document_id) if extension == ".pdf" else parse_csv(data, document_id)
    return document_id, hashlib.sha256(data).hexdigest(), bills

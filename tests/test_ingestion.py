from decimal import Decimal
from pathlib import Path

import pymupdf as fitz
import pytest

from utilityaudit.ingestion import IngestionError, ingest
from utilityaudit.storage import DuplicateDocumentError


def pdf_bytes(text: str) -> bytes:
    with fitz.open() as pdf:
        page = pdf.new_page()
        page.insert_text((50, 50), text)
        return pdf.tobytes()


def test_csv_preserves_identifiers_and_missing_values():
    _, _, bills = ingest("bill.csv", b"account_number,total_due,electricity_kwh\n001234,12.34,\n")
    assert bills[0].account_number == "001234"
    assert bills[0].total_due == Decimal("12.34")
    assert bills[0].electricity_kwh is None
    assert bills[0].quality["electricity_kwh"] == "missing"


@pytest.mark.parametrize(
    "data",
    [
        b"total_due,total_due\n1,1",
        b"total_due\nNaN",
        b"total_due\nInfinity",
        b"total_due\n1,2",
        b"total_due,bogus\n1,2",
        b"total_due\n",
        b"total_due,electricity_kwh\n1,-2",
        b"total_due,invoice_date\n1,01/02/2026",
        b"total_due,line_items_complete\n1,true",
        b"total_due\n\x00",
        b"total_due,period_start,period_end\n1,2026-02-01,2026-01-01",
        b'total_due,line_items\n1,"not json"',
    ],
)
def test_invalid_csv(data):
    with pytest.raises(IngestionError):
        ingest("bad.csv", data)


def test_pdf_explicit_labels_and_uncertainty():
    data = pdf_bytes(
        "Utility Provider: Synthetic Utility\nAccount Number: 001234\n"
        "Total Amount Due: $1,234.50\nElectricity Usage (kWh): 1000\n"
        "Invoice Date: 01/02/2026\nCurrency: USD\n"
    )
    bill = ingest("bill.pdf", data)[2][0]
    assert bill.total_due == Decimal("1234.50")
    assert bill.electricity_kwh == 1000
    assert bill.quality["invoice_date"] == "uncertain"
    assert bill.invoice_date is None
    assert not bill.line_items_complete


def test_conflicting_pdf_totals_not_guessed():
    bill = ingest("bill.pdf", pdf_bytes("Total Due: 10\nTotal Due: 20"))[2][0]
    assert bill.total_due is None
    assert bill.quality["total_due"] == "uncertain"


def test_empty_pdf_label_does_not_consume_next_field():
    bill = ingest("bill.pdf", pdf_bytes("Customer Name:\nAccount Number: 001234\nTotal Due: 10"))[2][0]
    assert bill.customer_name is None
    assert bill.account_number == "001234"


def test_excessively_nested_json_is_rejected():
    data = b"total_due,line_items\n1," + b"[" * 1100 + b"]" * 1100
    with pytest.raises(IngestionError, match="line_items"):
        ingest("nested.csv", data)


def test_pdf_billing_period_range_and_explicit_units():
    bill = ingest(
        "bill.pdf",
        pdf_bytes(
            "Billing Period: 2026-01-01 to 2026-01-31\n"
            "Electricity Usage: 1,000 kWh\nGas Usage: 10 therms\nTotal Due: 10"
        ),
    )[2][0]
    assert bill.days == 31
    assert bill.electricity_kwh == 1000
    assert bill.gas_therms == 10


def test_generic_pdf_usage_never_invents_units():
    bill = ingest("bill.pdf", pdf_bytes("Electricity Usage: 100\nGas Usage: 10\nTotal Due: 10"))[2][0]
    assert bill.electricity_kwh is None
    assert bill.gas_therms is None
    assert bill.quality["gas_therms"] == "uncertain"


def test_conflicting_period_labels_are_uncertain():
    bill = ingest(
        "bill.pdf", pdf_bytes("Billing Period: 2026-01-01 to 2026-01-31\nPeriod Start: 2026-01-02\nTotal Due: 10")
    )[2][0]
    assert bill.period_start is None
    assert bill.period_end is None
    assert bill.quality["period_start"] == "uncertain"


@pytest.mark.parametrize(
    "filename,data",
    [
        ("x.exe", b"data"),
        ("x.csv", b""),
        ("x.pdf", b"not a pdf"),
        ("x.pdf", b"%PDF-corrupt"),
        ("x.csv", b"\xff"),
    ],
)
def test_invalid_uploads(filename, data):
    with pytest.raises(IngestionError):
        ingest(filename, data)


def test_scanned_and_encrypted_pdf():
    with pytest.raises(IngestionError, match="OCR"):
        ingest("scan.pdf", pdf_bytes(""))
    with fitz.open() as pdf:
        pdf.new_page()
        data = pdf.tobytes(encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw="owner", user_pw="user")
    with pytest.raises(IngestionError, match="Password"):
        ingest("encrypted.pdf", data)


def test_storage_atomic_import_roundtrip_and_delete(repo):
    data = Path("samples/bills.csv").read_bytes()
    assert repo.import_document("../../bills.csv", data) == 4
    assert repo.bills()[0].account_number == "00123456"
    assert repo.bills()[0].period_start.isoformat() == "2026-01-01"
    with pytest.raises(DuplicateDocumentError):
        repo.import_document("renamed.csv", data)
    with pytest.raises(IngestionError):
        repo.import_document("invalid.csv", b"total_due\n1\nbroken")
    assert len(repo.documents()) == 1
    document = repo.documents()[0]
    assert document["name"] == "bills.csv"
    assert repo.document_content(document["id"]) == data
    repo.delete_document(document["id"])
    assert not repo.bills()
    assert not repo.documents()

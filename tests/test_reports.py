import csv
import io
import unicodedata
from pathlib import Path

import pymupdf as fitz

from utilityaudit.audit import audit
from utilityaudit.ingestion import ingest
from utilityaudit.models import AuditConfig
from utilityaudit.reports import export_csv, export_pdf, safe_cell


def sample_bills():
    return ingest("sample.csv", Path("samples/bills.csv").read_bytes())[2]


def test_csv_complete_report_and_masked_accounts():
    bills = sample_bills()
    findings = audit(bills)
    data = export_csv(bills, findings, AuditConfig())
    text = data.decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert {row["record_type"] for row in rows} == {"report", "bill", "finding", "impact_summary", "coverage"}
    assert sum(row["record_type"] == "bill" for row in rows) == 4
    assert sum(row["record_type"] == "finding" for row in rows) == len(findings)
    assert "00123456" not in text
    assert "****3456" in text
    assert "not confirmed" in text
    assert all(row["evidence"] and row["recommended_action"] for row in rows if row["record_type"] == "finding")


def test_csv_formula_injection_defense():
    for value in ("=1+1", " +1", "-2", "@SUM(A1)", "\tformula", "\nformula"):
        assert safe_cell(value).startswith("'")
    bills = sample_bills()
    bills[0].customer_name = '=HYPERLINK("example")'
    text = export_csv(bills, [], AuditConfig()).decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert next(row for row in rows if row["record_type"] == "bill")["customer"].startswith("'=")


def test_pdf_multipage_content_and_masking():
    bills = sample_bills()
    bills[0].customer_name = "Café <Workshop>"
    findings = audit(bills)
    data = export_pdf(bills, findings, AuditConfig())
    assert data.startswith(b"%PDF")
    with fitz.open(stream=data, filetype="pdf") as document:
        assert len(document) > 1
        text = " ".join(unicodedata.normalize("NFKC", "\n".join(page.get_text() for page in document)).split())
        assert "00123456" not in text
        assert "****3456" in text
        assert "Café <Workshop>" in text
        assert "Recommended action:" in text
        assert "arithmetic_tolerance" in text
        assert "not confirmed" in text
        assert "Calculation verified; source data and liability unverified" in text
        for bill in bills:
            assert bill.reference in text
        assert f"Page {len(document)} of {len(document)}" in text


def test_empty_report_does_not_claim_accuracy():
    with fitz.open(stream=export_pdf([], [], AuditConfig()), filetype="pdf") as document:
        text = " ".join(unicodedata.normalize("NFKC", "\n".join(page.get_text() for page in document)).split())
        assert "No findings under the configured rules" in text
        assert "does not certify billing accuracy" in text

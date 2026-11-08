import time
from datetime import date
from decimal import Decimal

import pytest
from test_audit import bill
from test_ingestion import pdf_bytes

from utilityaudit.audit import analyze, audit
from utilityaudit.history import monthly_history
from utilityaudit.ingestion import correct_bill, ingest
from utilityaudit.models import AuditConfig, LineItem


def test_source_provenance_and_correction_preserves_original():
    original = ingest("bill.pdf", pdf_bytes("Total Due: 10\nCurrency: USD"))[2][0]
    source = original.provenance["total_due"][0]
    assert source["page"] == 1 and source["text"] == "Total Due: 10"
    corrected = correct_bill(original, {"total_due": "12.34"}, [])
    assert corrected.version == 2 and corrected.total_due == Decimal("12.34")
    assert corrected.quality["total_due"] == "verified"
    assert corrected.provenance == original.provenance
    assert original.total_due == 10 and original.version == 1
    with pytest.raises(ValueError):
        correct_bill(original, {"document_id": "different"}, [])


def test_explicit_replacement_not_duplicate_or_double_spending():
    original = bill()
    replacement = bill(
        invoice_number="I-REVISED",
        invoice_kind="replacement",
        supersedes_invoice_number=original.invoice_number,
        invoice_date=date(2026, 2, 1),
        due_date=date(2026, 2, 20),
    )
    result = analyze([original, replacement])
    assert original.id in result.exclusions
    assert not any(item.code in ("duplicate_invoice", "overlapping_period") for item in result.findings)
    assert monthly_history([original, replacement])["Spending"].sum() == 150


def test_unresolved_replacement_requires_review():
    replacement = bill(invoice_kind="replacement", supersedes_invoice_number="NOT-FOUND")
    result = analyze([replacement])
    assert [item.code for item in result.findings] == ["unresolved_revision"]
    assert replacement.id in result.exclusions
    assert monthly_history([replacement]).empty


def test_service_and_meter_references_prevent_false_duplicates():
    first, second = bill(meter_id="A"), bill(meter_id="B")
    assert audit([first, second]) == []
    items = [LineItem("Delivery", Decimal("20"), "delivery", "A"), LineItem("Delivery", Decimal("20"), "delivery", "B")]
    assert not any(item.code == "duplicate_charge" for item in audit([bill(line_items=items)]))


def test_balance_and_current_charge_math_are_separate():
    invoice = bill(
        total_basis="amount_due",
        total_due=Decimal("170"),
        current_charges=Decimal("150"),
        previous_balance=Decimal("100"),
        payments=Decimal("50"),
        credits=Decimal("30"),
    )
    assert audit([invoice]) == []
    invoice.total_due = Decimal("180")
    finding = audit([invoice])[0]
    assert finding.code == "balance_discrepancy"
    assert finding.evidence["expected_amount_due"] == 170
    assert finding.estimated_impact == 10
    assert monthly_history([invoice]).iloc[0]["Spending"] == 150


def test_coverage_identifies_unavailable_checks_without_claiming_pass():
    result = analyze([bill()])
    assert not result.findings
    assert any(
        item.check == "bill_increase" and item.status == "skipped" and "have 0" in item.reason
        for item in result.coverage
    )
    assert any(item.check == "arithmetic_discrepancy" and item.status == "checked" for item in result.coverage)


def test_same_month_baseline_requires_earlier_years():
    bills = []
    for year in range(2023, 2027):
        bills.append(
            bill(
                invoice_number=str(year),
                period_start=date(year, 1, 1),
                period_end=date(year, 1, 28),
                electricity_kwh=Decimal("1000" if year < 2026 else "2000"),
            )
        )
    result = analyze(bills, AuditConfig(baseline_mode="same_month"))
    finding = next(item for item in result.findings if item.code == "usage_change")
    assert finding.evidence["baseline_bill_count"] == 3
    assert finding.evidence["baseline_mode"] == "same_month"
    assert not any(
        item.code == "usage_change" for item in analyze(bills[:3], AuditConfig(baseline_mode="same_month")).findings
    )


def test_review_key_invalidates_after_any_input_correction():
    bills = [bill(total_due=Decimal("200"))]
    before = analyze(bills).findings[0].key
    bills[0] = correct_bill(bills[0], {"total_due": "201"}, [])
    assert analyze(bills).findings[0].key != before
    assert analyze(bills).findings[0].key == analyze(bills).findings[0].key


@pytest.mark.performance
def test_five_thousand_overlaps_have_bounded_output():
    bills = [bill(invoice_number=f"LOAD-{index}") for index in range(5000)]
    start = time.monotonic()
    result = analyze(bills)
    elapsed = time.monotonic() - start
    assert len(result.findings) == 4999
    assert all(len(item.related_bill_ids) <= 10 for item in result.findings)
    assert elapsed < 15, f"5000-bill analysis took {elapsed:.2f}s"

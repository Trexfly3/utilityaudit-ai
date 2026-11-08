from datetime import date
from decimal import Decimal

import pytest

from utilityaudit.audit import audit, effective_rate, estimated_impact
from utilityaudit.history import monthly_history
from utilityaudit.models import EXTRACTED_FIELDS, AuditConfig, Bill, LineItem


def bill(month=1, **overrides):
    defaults = dict(
        provider="Utility",
        account_number="001",
        customer_name="Test",
        invoice_number=f"I-{month}",
        currency="USD",
        utility_type="electricity",
        total_basis="current_charges",
        period_start=date(2026, month, 1),
        period_end=date(2026, month, 28),
        invoice_date=date(2026, month, 28),
        due_date=date(2026, month, 28),
        electricity_kwh=Decimal("1000"),
        base_charges=Decimal("10"),
        delivery_charges=Decimal("30"),
        energy_charges=Decimal("100"),
        taxes=Decimal("10"),
        additional_fees=Decimal("0"),
        total_due=Decimal("150"),
        line_items_complete=True,
    )
    defaults.update(overrides)
    result = Bill(**defaults)
    result.quality = {
        name: "extracted" if getattr(result, name) is not None else "missing" for name in EXTRACTED_FIELDS
    }
    return result


def codes(bills):
    return [finding.code for finding in audit(bills)]


def test_normal_bills_have_no_findings():
    assert audit([bill(month) for month in range(1, 5)]) == []


def test_duplicate_invoice_is_account_scoped_and_not_confirmed_error():
    first, second = bill(), bill()
    result = audit([first, second])
    assert [item.code for item in result] == ["duplicate_invoice"]
    assert result[0].classification == "Potential billing anomaly"
    assert "duplicate_invoice" not in codes([first, bill(account_number="002")])
    assert "duplicate_invoice" not in codes([first, bill(provider="Different Utility")])


def test_missing_identity_does_not_group_unrelated_bills():
    assert "duplicate_invoice" not in codes([bill(account_number=None), bill(account_number=None)])
    assert "overlapping_period" not in codes([bill(account_number=None), bill(account_number=None)])


def test_fingerprint_duplicate_requires_usage():
    assert "duplicate_invoice" in codes([bill(invoice_number=None), bill(invoice_number=None)])
    assert "duplicate_invoice" not in codes(
        [
            bill(invoice_number=None, electricity_kwh=None),
            bill(invoice_number=None, electricity_kwh=None),
        ]
    )


def test_duplicate_charge_flags_not_convicts():
    repeated = LineItem("Delivery", Decimal("20"), "delivery")
    result = audit([bill(line_items=[repeated, repeated], line_items_complete=False)])
    charge = next(item for item in result if item.code == "duplicate_charge")
    assert charge.estimated_impact == 20
    assert charge.verification == "Human verification required"


def test_exact_arithmetic_and_tolerance():
    assert "arithmetic_discrepancy" not in codes([bill(total_due=Decimal("150.02"))])
    result = audit([bill(total_due=Decimal("150.03"))])
    discrepancy = next(item for item in result if item.code == "arithmetic_discrepancy")
    assert discrepancy.evidence["difference"] == Decimal("0.03")
    assert discrepancy.classification == "Confirmed mathematical discrepancy"
    assert "arithmetic_discrepancy" not in codes([bill(total_due=Decimal("200"), line_items_complete=False)])
    assert "arithmetic_discrepancy" not in codes([bill(total_due=Decimal("200"), total_basis="amount_due")])


def test_line_items_take_precedence_and_credits_count():
    items = [LineItem("Energy", Decimal("160"), "energy"), LineItem("Credit", Decimal("-10"), "credit")]
    assert "arithmetic_discrepancy" not in codes([bill(line_items=items)])


def test_history_anomalies_all_metrics():
    bills = [bill(month) for month in range(1, 4)]
    bills.append(bill(4, total_due=Decimal("450"), electricity_kwh=Decimal("2000"), energy_charges=Decimal("400")))
    result = audit(bills)
    assert {"bill_increase", "usage_change", "rate_change"} <= {item.code for item in result}
    increase = next(item for item in result if item.code == "bill_increase")
    assert increase.evidence["baseline_bill_count"] == 3
    assert increase.evidence["percent_change"].quantize(Decimal("0.01")) == Decimal("200.00")
    assert all(item.description and item.recommendation and item.evidence and item.reference for item in result)


def test_short_history_and_zero_baseline_not_flagged():
    bills = [bill(1), bill(2, electricity_kwh=Decimal("99999"))]
    assert "usage_change" not in codes(bills)
    bills = [bill(month, electricity_kwh=Decimal("0")) for month in range(1, 4)] + [bill(4)]
    assert "usage_change" not in codes(bills)
    assert effective_rate(bills[0]) is None


def test_billing_days_normalize_comparisons():
    bills = [bill(month) for month in range(1, 4)]
    bills.append(
        bill(
            4,
            period_end=date(2026, 4, 14),
            electricity_kwh=Decimal("500"),
            total_due=Decimal("75"),
            base_charges=Decimal("5"),
            delivery_charges=Decimal("15"),
            energy_charges=Decimal("50"),
            taxes=Decimal("5"),
        )
    )
    assert audit(bills) == []


def test_overlap_excluded_from_baseline():
    bills = [bill(month) for month in range(1, 4)]
    bills.append(bill(4, period_start=date(2026, 3, 25), electricity_kwh=Decimal("5000")))
    findings = audit(bills)
    overlap = next(item for item in findings if item.code == "overlapping_period")
    assert overlap.evidence["overlap_days"] == 4
    assert "usage_change" not in {item.code for item in findings}


def test_mixed_utility_rate_unavailable():
    assert effective_rate(bill(utility_type="mixed")) is None
    assert effective_rate(bill(utility_type=None)) is None
    assert effective_rate(bill(gas_therms=Decimal("10"))) is None


def test_impact_not_double_counted_and_currency_separate():
    usd = bill(
        total_due=Decimal("200"),
        line_items=[
            LineItem("Fee", Decimal("50"), "fee"),
            LineItem("Fee", Decimal("50"), "fee"),
        ],
    )
    eur = bill(account_number="002", currency="EUR", total_due=Decimal("160"))
    assert estimated_impact([usd, eur], audit([usd, eur])) == {"USD": Decimal("100"), "EUR": Decimal("10")}


def test_monthly_weighted_rate_duplicates_and_gaps():
    bills = [bill(), bill(), bill(account_number="002", electricity_kwh=Decimal("2000")), bill(3)]
    frame = monthly_history(bills)
    assert frame.iloc[0]["Spending"] == 300
    assert abs(frame.iloc[0]["Average price/kWh"] - 280 / 3000) < 1e-10
    assert frame.iloc[1]["Spending change %"] != frame.iloc[1]["Spending change %"]  # NaN: calendar gap


def test_usage_decrease_and_water_unit_isolation():
    bills = [bill(month) for month in range(1, 4)] + [bill(4, electricity_kwh=Decimal("100"))]
    assert "usage_change" in codes(bills)
    water = [bill(month, water_usage=Decimal("100"), water_unit="gallons") for month in range(1, 4)]
    water.append(bill(4, water_usage=Decimal("9999"), water_unit="m3"))
    assert not any(item.code == "usage_change" and item.evidence["metric"] == "water_usage" for item in audit(water))


def test_historical_dates_outside_pandas_nanosecond_range():
    old = bill(invoice_date=date(1600, 1, 15))
    newer = bill(2, invoice_date=date(1600, 2, 15))
    frame = monthly_history([old, newer])
    assert frame.iloc[1]["Spending change %"] == 0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"bill_increase_pct": float("nan")},
        {"usage_change_pct": 0},
        {"rate_change_pct": float("inf")},
        {"min_history": 2},
        {"arithmetic_tolerance": "NaN"},
        {"arithmetic_tolerance": "-1"},
    ],
)
def test_invalid_config(kwargs):
    with pytest.raises(ValueError):
        AuditConfig(**kwargs)


def test_uncertain_values_are_not_used_as_reliable_evidence():
    uncertain = bill(total_due=Decimal("999"))
    uncertain.quality["total_due"] = "uncertain"
    result = audit([uncertain])
    assert [item.code for item in result] == ["missing_information"]


def test_duplicates_cannot_supply_extra_baseline_bills():
    bills = [bill(1), bill(1), bill(2), bill(4, electricity_kwh=Decimal("10000"))]
    assert "usage_change" not in codes(bills)


def test_currencies_are_not_compared_or_added():
    bills = [bill(month) for month in range(1, 4)]
    bills.append(bill(4, currency="EUR", electricity_kwh=Decimal("10000")))
    assert "usage_change" not in codes(bills)
    frame = monthly_history([bill(), bill(account_number="002", currency="EUR")])
    assert sorted(frame["Spending"]) == [150, 150]


def test_exact_threshold_not_flagged_by_division_rounding():
    bills = [bill(month, total_due=Decimal("1"), electricity_kwh=Decimal("1")) for month in range(1, 4)]
    bills.append(bill(4, total_due=Decimal("1.3"), electricity_kwh=Decimal("1.3")))
    result = codes(bills)
    assert "bill_increase" not in result
    assert "usage_change" not in result
    bills[-1].total_due = Decimal("1.30000001")
    assert "bill_increase" in codes(bills)


def test_unknown_currencies_never_aggregate():
    bills = [bill(currency=None, total_due=Decimal("200")), bill(2, currency=None, total_due=Decimal("300"))]
    assert estimated_impact(bills, audit(bills)) == {}

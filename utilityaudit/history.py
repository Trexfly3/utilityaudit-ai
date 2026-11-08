"""Historical tables. Decimal calculations stay in the domain layer."""

import pandas as pd

from utilityaudit.audit import current_charges, duplicate_candidates, effective_rate, revision_exclusions
from utilityaudit.models import Bill, mask_account


def bill_table(bills: list[Bill]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "Reference": bill.reference,
                "Provider": bill.provider,
                "Account": mask_account(bill.account_number),
                "Currency": bill.currency,
                "Version": bill.version,
                "Service": bill.service_id,
                "Meter": bill.meter_id,
                "Invoice date": bill.invoice_date,
                "Period start": bill.period_start,
                "Period end": bill.period_end,
                "Total due": float(bill.total_due) if bill.reliable("total_due") else None,
                "Electricity kWh": float(bill.electricity_kwh) if bill.reliable("electricity_kwh") else None,
                "Effective price/kWh": float(rate) if (rate := effective_rate(bill)) is not None else None,
            }
            for bill in bills
        ]
    )


def monthly_history(bills: list[Bill]) -> pd.DataFrame:
    excluded = revision_exclusions(bills)
    duplicates = duplicate_candidates([bill for bill in bills if bill.id not in excluded])
    rows = []
    for bill in bills:
        when = (
            bill.invoice_date
            if bill.reliable("invoice_date")
            else (bill.period_end if bill.reliable("period_end") else None)
        )
        if when is None or bill.id in duplicates or bill.id in excluded or not bill.reliable("currency"):
            continue
        rate = effective_rate(bill)
        rows.append(
            {
                "Month": when.strftime("%Y-%m"),
                "Currency": bill.currency,
                "Spending": float(value) if (value := current_charges(bill)) is not None else None,
                "Bills": 1,
                "Bills with current charges": int(value is not None),
                "Electricity kWh": float(bill.electricity_kwh) if bill.reliable("electricity_kwh") else None,
                "Gas therms": float(bill.gas_therms) if bill.reliable("gas_therms") else None,
                "Rate cost": float(rate * bill.electricity_kwh) if rate is not None else None,
                "Rate kWh": float(bill.electricity_kwh) if rate is not None else None,
            }
        )
    if not rows:
        return pd.DataFrame()
    frame = pd.DataFrame(rows).groupby(["Month", "Currency"], as_index=False).sum(min_count=1)
    frame["Average price/kWh"] = frame["Rate cost"] / frame["Rate kWh"]
    # Compare consecutive calendar months only; gaps are not month-over-month changes.
    for column in ("Spending", "Electricity kWh", "Average price/kWh"):
        previous = frame.groupby("Currency")[column].shift()
        month_ordinals = pd.Series(pd.PeriodIndex(frame["Month"], freq="M").asi8, index=frame.index)
        previous_month = month_ordinals.groupby(frame["Currency"]).shift()
        consecutive = month_ordinals - previous_month == 1
        frame[f"{column} change %"] = ((frame[column] - previous) / previous * 100).where((previous > 0) & consecutive)
    return frame.drop(columns=["Rate cost", "Rate kWh"])

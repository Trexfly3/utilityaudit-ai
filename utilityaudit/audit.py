"""Pure, deterministic analysis with explicit rule coverage and exact thresholds."""

import hashlib
import heapq
import json
from collections import defaultdict, deque
from dataclasses import asdict
from decimal import Decimal
from fractions import Fraction
from itertools import islice
from statistics import median
from typing import Iterable

from utilityaudit.models import (
    CHARGE_FIELDS,
    RULE_VERSION,
    AuditConfig,
    AuditResult,
    Bill,
    CheckCoverage,
    Finding,
    bill_to_json,
)

ZERO = Decimal("0")
USAGE_FIELDS = ("electricity_kwh", "gas_therms", "water_usage")


def account_key(bill: Bill) -> tuple | None:
    if not bill.reliable("provider", "account_number", "currency"):
        return None
    return (" ".join(bill.provider.casefold().split()), bill.account_number.strip(), bill.currency)


def service_key(bill: Bill) -> tuple | None:
    key = account_key(bill)
    if key is None or any(bill.quality.get(name) == "uncertain" for name in ("service_id", "meter_id", "utility_type")):
        return None
    return (*key, bill.utility_type, bill.service_id, bill.meter_id)


def valid_period(bill: Bill) -> bool:
    return bill.reliable("period_start", "period_end") and bill.days is not None and bill.days > 0


def current_charges(bill: Bill) -> Decimal | None:
    if bill.reliable("total_basis", "total_due") and bill.total_basis == "current_charges":
        return bill.total_due
    if bill.reliable("current_charges"):
        return bill.current_charges
    return None


def effective_rate(bill: Bill) -> Decimal | None:
    if (
        not bill.reliable("utility_type", "electricity_kwh", "base_charges", "delivery_charges", "energy_charges")
        or bill.utility_type != "electricity"
        or bill.electricity_kwh <= 0
        or bill.gas_therms is not None
        or bill.water_usage is not None
        or any(bill.quality.get(name) == "uncertain" for name in ("gas_therms", "water_usage"))
    ):
        return None
    cost = sum((getattr(bill, name) for name in ("base_charges", "delivery_charges", "energy_charges")), ZERO)
    return cost / bill.electricity_kwh if cost > 0 else None


def invoice_fingerprint(bill: Bill) -> tuple | None:
    if not valid_period(bill) or not bill.reliable("total_due"):
        return None
    if not any(bill.reliable(name) for name in USAGE_FIELDS):
        return None
    if any(bill.quality.get(name) == "uncertain" for name in USAGE_FIELDS):
        return None
    return (
        bill.period_start,
        bill.period_end,
        bill.total_due,
        *(getattr(bill, name) for name in USAGE_FIELDS),
        bill.water_unit,
    )


def duplicate_of(bill: Bill, previous: Bill) -> bool:
    if service_key(bill) is None or service_key(bill) != service_key(previous):
        return False
    if bill.reliable("invoice_number") and previous.reliable("invoice_number"):
        return bill.invoice_number == previous.invoice_number
    fingerprint = invoice_fingerprint(bill)
    return fingerprint is not None and fingerprint == invoice_fingerprint(previous)


def duplicate_candidates(bills: Iterable[Bill]) -> dict[str, Bill]:
    by_number: dict[tuple, Bill] = {}
    by_fingerprint: dict[tuple, Bill] = {}
    without_number: dict[tuple, Bill] = {}
    matches = {}
    for bill in bills:
        key = service_key(bill)
        if key is None:
            continue
        number = bill.invoice_number if bill.reliable("invoice_number") else None
        fingerprint = invoice_fingerprint(bill)
        match = by_number.get((key, number)) if number else None
        if match is None and fingerprint is not None:
            match = (without_number if number else by_fingerprint).get((key, fingerprint))
        if match:
            matches[bill.id] = match
            continue
        if number:
            by_number.setdefault((key, number), bill)
        if fingerprint is not None:
            by_fingerprint.setdefault((key, fingerprint), bill)
            if not number:
                without_number.setdefault((key, fingerprint), bill)
    return matches


def revision_exclusions(bills: list[Bill]) -> dict[str, str]:
    """Only explicit, unambiguous replacements suppress an earlier invoice."""
    indexed: dict[tuple, list[Bill]] = defaultdict(list)
    for bill in bills:
        if service_key(bill) is not None and bill.reliable("invoice_number"):
            indexed[(service_key(bill), bill.invoice_number)].append(bill)
    exclusions = {}
    for bill in bills:
        if bill.invoice_kind == "credit":
            exclusions[bill.id] = (
                "Credit note: reconcile with applied balance credits; excluded from spending/usage baselines."
            )
        elif bill.invoice_kind == "replacement" or bill.supersedes_invoice_number:
            candidates = indexed.get((service_key(bill), bill.supersedes_invoice_number), [])
            candidates = [
                old
                for old in candidates
                if old.id != bill.id
                and old.reliable("invoice_date")
                and bill.reliable("invoice_date")
                and old.invoice_date < bill.invoice_date
                and valid_period(old)
                and valid_period(bill)
                and (old.period_start, old.period_end) == (bill.period_start, bill.period_end)
            ]
            if len(candidates) == 1 and bill.reliable("supersedes_invoice_number"):
                exclusions[candidates[0].id] = f"Superseded by declared replacement {bill.reference}."
            else:
                exclusions[bill.id] = (
                    "Unresolved replacement: identify one older invoice with the same service and billing period."
                )
    return exclusions


def finding(
    bill: Bill, code: str, description: str, evidence: dict, explanation: str, recommendation: str, **kwargs
) -> Finding:
    return Finding(
        code=code,
        bill_id=bill.id,
        reference=bill.reference,
        description=description,
        evidence=evidence,
        explanation=explanation,
        recommendation=recommendation,
        severity=kwargs.pop("severity", "warning"),
        classification=kwargs.pop("classification", "Potential billing anomaly"),
        **kwargs,
    )


def decimal_value(value: Fraction | int) -> Decimal:
    return Decimal(value.numerator) / Decimal(value.denominator)


def metric_value(bill: Bill, name: str) -> Fraction | None:
    if name == "effective_rate":
        if effective_rate(bill) is None:
            return None
        cost = sum((getattr(bill, field) for field in ("base_charges", "delivery_charges", "energy_charges")), ZERO)
        return Fraction(cost) / Fraction(bill.electricity_kwh)
    if not valid_period(bill):
        return None
    if name == "total_due":
        value = current_charges(bill)
    else:
        value = getattr(bill, name) if bill.reliable(name) else None
    if value is None or (name == "water_usage" and not bill.reliable("water_unit")):
        return None
    return Fraction(value) / bill.days


def analyze(bills: list[Bill], config: AuditConfig | None = None) -> AuditResult:
    config = config or AuditConfig()
    config.__post_init__()
    digest = hashlib.sha256(json.dumps([RULE_VERSION, asdict(config)], sort_keys=True).encode())
    for bill in sorted(bills, key=lambda value: value.id):
        digest.update(bill_to_json(bill).encode())
    result = AuditResult(input_digest=digest.hexdigest(), exclusions=revision_exclusions(bills))
    findings = result.findings

    def coverage(bill: Bill, code: str, status: str, reason: str, metric: str | None = None) -> None:
        result.coverage.append(CheckCoverage(bill.id, bill.reference, code, status, reason, metric))

    active = [bill for bill in bills if bill.id not in result.exclusions]
    duplicates = duplicate_candidates(active)
    comparable: dict[tuple, list[Bill]] = defaultdict(list)
    metrics = [
        ("total_due", config.bill_increase_pct, "bill_increase", True),
        ("electricity_kwh", config.usage_change_pct, "usage_change", False),
        ("gas_therms", config.usage_change_pct, "usage_change", False),
        ("water_usage", config.usage_change_pct, "usage_change", False),
        ("effective_rate", config.rate_change_pct, "rate_change", False),
    ]
    for bill in bills:
        required = (
            "provider",
            "account_number",
            "invoice_number",
            "currency",
            "period_start",
            "period_end",
            "invoice_date",
            "due_date",
            "total_due",
            "total_basis",
            "utility_type",
        )
        missing = [name for name in required if not bill.reliable(name)]
        if not any(bill.reliable(name) for name in USAGE_FIELDS):
            missing.append("utility_usage")
        if bill.water_usage is not None and not bill.reliable("water_unit"):
            missing.append("water_unit")
        if not bill.line_items_complete:
            missing.append("complete_line_item_coverage")
        uncertain = sorted(name for name, quality in bill.quality.items() if quality == "uncertain")
        coverage(
            bill,
            "missing_information",
            "flagged" if missing or uncertain else "checked",
            "Required fields and extraction confidence inspected.",
        )
        if missing or uncertain:
            findings.append(
                finding(
                    bill,
                    "missing_information",
                    "Information is missing or requires verification.",
                    {
                        "missing_or_unreliable_fields": missing,
                        "uncertain_fields": uncertain,
                        "field_count": len(set(missing + uncertain)),
                    },
                    "Missing values are not zero. Consult rule coverage for checks that could not run.",
                    "Review original evidence and correct or verify individual fields.",
                    severity="info",
                    classification="Requires human verification",
                    confidence="high",
                )
            )
        if bill.id in result.exclusions:
            reason = result.exclusions[bill.id]
            coverage(bill, "invoice_revision", "skipped", reason)
            if reason.startswith("Unresolved"):
                findings.append(
                    finding(
                        bill,
                        "unresolved_revision",
                        "Replacement invoice could not be linked safely.",
                        {
                            "invoice_version": bill.version,
                            "replacement_reference_supplied": bool(bill.supersedes_invoice_number),
                        },
                        reason,
                        "Verify the replacement reference, service, dates and original invoice.",
                        severity="info",
                        classification="Requires human verification",
                    )
                )
            for code in (
                "duplicate_invoice",
                "duplicate_charge",
                "arithmetic_discrepancy",
                "balance_discrepancy",
                "overlapping_period",
            ):
                coverage(bill, code, "skipped", reason)
            for metric, _, code, _ in metrics:
                coverage(bill, code, "skipped", reason, metric)
            continue
        match = duplicates.get(bill.id)
        can_duplicate = service_key(bill) is not None and (
            bill.reliable("invoice_number") or invoice_fingerprint(bill) is not None
        )
        coverage(
            bill,
            "duplicate_invoice",
            "flagged" if match else ("checked" if can_duplicate else "skipped"),
            "Compared within account, currency and service/meter scope."
            if can_duplicate
            else "Reliable identity and invoice number or usage fingerprint required.",
        )
        if match:
            findings.append(
                finding(
                    bill,
                    "duplicate_invoice",
                    "Possible duplicate invoice or undeclared revision.",
                    {
                        "matching_reference": match.reference,
                        "current_total": bill.total_due,
                        "previous_total": match.total_due,
                        "matching_invoice_number": bool(
                            bill.invoice_number and bill.invoice_number == match.invoice_number
                        ),
                    },
                    "The service-scoped invoice identifier or period/total/usage fingerprint matches. "
                    "Repeated imports and revised bills do not prove duplicate payment.",
                    "Check original documents and payment records; explicitly link replacement invoices.",
                    estimated_impact=max(bill.total_due, ZERO) if bill.reliable("total_due") else None,
                    related_bill_ids=[match.id],
                )
            )
        item_groups: dict[tuple, list] = defaultdict(list)
        for item in bill.line_items:
            if item.amount > 0:
                item_groups[
                    (
                        " ".join(item.description.casefold().split()),
                        item.category.casefold().strip(),
                        item.amount,
                        item.service_reference,
                    )
                ].append(item)
        repeated = [items for items in item_groups.values() if len(items) > 1]
        coverage(
            bill,
            "duplicate_charge",
            "flagged" if repeated else ("checked" if bill.line_items else "skipped"),
            "Compared explicit items including service references."
            if bill.line_items
            else "No explicit line items supplied.",
        )
        if repeated:
            impact = sum((items[0].amount * (len(items) - 1) for items in repeated), ZERO)
            findings.append(
                finding(
                    bill,
                    "duplicate_charge",
                    "Repeated identical positive line items.",
                    {
                        "groups": [
                            {"description": items[0].description, "amount": items[0].amount, "count": len(items)}
                            for items in repeated
                        ],
                        "repeated_amount": impact,
                    },
                    "Matching descriptions, amounts and service references may be duplicate charges or legitimate repeated services.",
                    "Verify quantities, meter identifiers and service periods for the repeated items.",
                    estimated_impact=impact,
                )
            )
        target = current_charges(bill)
        amounts = (
            [item.amount for item in bill.line_items]
            if bill.line_items
            else [getattr(bill, name) for name in CHARGE_FIELDS if bill.reliable(name)]
        )
        arithmetic_ready = (
            target is not None
            and bill.line_items_complete
            and (bool(bill.line_items) or len(amounts) == len(CHARGE_FIELDS))
        )
        difference = target - sum(amounts, ZERO) if arithmetic_ready else ZERO
        mismatch = arithmetic_ready and abs(difference) > Decimal(config.arithmetic_tolerance)
        coverage(
            bill,
            "arithmetic_discrepancy",
            "flagged" if mismatch else ("checked" if arithmetic_ready else "skipped"),
            "Complete item sum compared with current charges."
            if arithmetic_ready
            else "Reliable current charges and explicitly complete items are required.",
        )
        if mismatch:
            findings.append(
                finding(
                    bill,
                    "arithmetic_discrepancy",
                    "Invoice current charges differ from the declared complete charge sum.",
                    {
                        "line_item_sum": sum(amounts, ZERO),
                        "invoice_total": target,
                        "difference": difference,
                        "tolerance": config.arithmetic_tolerance,
                        "item_count": len(amounts),
                    },
                    "Exact addition confirms disagreement in the supplied numbers, not a provider error.",
                    "Verify transcription, completeness, credits and adjustments against the original invoice.",
                    severity="high",
                    classification="Confirmed mathematical discrepancy",
                    confidence="high",
                    verification="Calculation verified; source data and liability unverified",
                    estimated_impact=max(difference, ZERO),
                )
            )
        balance_ready = bill.total_basis == "amount_due" and bill.reliable(
            "total_basis", "total_due", "current_charges", "previous_balance", "payments", "credits"
        )
        expected = (
            bill.current_charges + bill.previous_balance - bill.payments - bill.credits if balance_ready else None
        )
        balance_mismatch = balance_ready and abs(bill.total_due - expected) > Decimal(config.arithmetic_tolerance)
        coverage(
            bill,
            "balance_discrepancy",
            "flagged" if balance_mismatch else ("checked" if balance_ready else "skipped"),
            "Amount due = current charges + previous balance - payments - credits."
            if balance_ready
            else "Balance arithmetic requires explicit current charges, prior balance, payments and credits.",
        )
        if balance_mismatch:
            findings.append(
                finding(
                    bill,
                    "balance_discrepancy",
                    "Amount due does not reconcile with the declared balance components.",
                    {
                        "expected_amount_due": expected,
                        "amount_due": bill.total_due,
                        "current_charges": bill.current_charges,
                        "previous_balance": bill.previous_balance,
                        "payments": bill.payments,
                        "credits": bill.credits,
                        "difference": bill.total_due - expected,
                    },
                    "The documented balance equation does not reconcile. Unrecorded adjustments may explain it.",
                    "Verify the balance brought forward, payment postings, credit notes and all adjustments.",
                    severity="high",
                    classification="Confirmed mathematical discrepancy",
                    confidence="high",
                    verification="Calculation verified; source data and liability unverified",
                    estimated_impact=max(bill.total_due - expected, ZERO),
                )
            )
        if not match and service_key(bill) is not None and valid_period(bill):
            comparable[service_key(bill)].append(bill)
        else:
            reason = "Duplicate candidate or unreliable account/service identity or billing period."
            coverage(bill, "overlapping_period", "skipped", reason)
            for metric, _, code, _ in metrics:
                coverage(bill, code, "skipped", reason, metric)

    for group in comparable.values():
        group.sort(key=lambda bill: (bill.period_start, bill.period_end, bill.id))
        active_periods: dict[str, Bill] = {}
        ends: list[tuple] = []
        overlapping: set[str] = set()
        for bill in group:
            while ends and ends[0][0] < bill.period_start:
                _, expired = heapq.heappop(ends)
                active_periods.pop(expired, None)
            if active_periods:
                previous = next(iter(active_periods.values()))
                overlapping.update((bill.id, previous.id))
                findings.append(
                    finding(
                        bill,
                        "overlapping_period",
                        "Billing periods overlap within the same service.",
                        {
                            "overlap_days": (min(previous.period_end, bill.period_end) - bill.period_start).days + 1,
                            "previous_reference": previous.reference,
                            "overlapping_prior_count": len(active_periods),
                            "previous_period": f"{previous.period_start} to {previous.period_end}",
                            "current_period": f"{bill.period_start} to {bill.period_end}",
                        },
                        "Dates are inclusive. Evidence shows one overlapping interval; shared boundaries or revisions may explain it.",
                        "Verify service identifiers, replacement relationships and the provider's boundary convention.",
                        related_bill_ids=list(islice(active_periods, 10)),
                    )
                )
            active_periods[bill.id] = bill
            heapq.heappush(ends, (bill.period_end, bill.id))
        history: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=config.min_history))
        seasonal: dict[tuple, dict[int, tuple]] = defaultdict(dict)
        for bill in group:
            coverage(
                bill,
                "overlapping_period",
                "flagged" if bill.id in overlapping else "checked",
                "Overlapping participants excluded from historical baselines."
                if bill.id in overlapping
                else "No service-scoped date overlap found.",
            )
            for metric, threshold, code, increase_only in metrics:
                value = metric_value(bill, metric)
                if bill.id in overlapping or value is None or value < 0:
                    coverage(
                        bill,
                        code,
                        "skipped",
                        "Overlapping period or missing/incompatible/nonpositive-billing data.",
                        metric,
                    )
                    continue
                key = (metric, bill.water_unit if metric == "water_usage" else None)
                if config.baseline_mode == "same_month":
                    yearly = seasonal[(*key, bill.period_end.month)]
                    prior = [yearly[year] for year in sorted(yearly) if year < bill.period_end.year][
                        -config.min_history :
                    ]
                else:
                    prior = list(history[key])
                if len(prior) < config.min_history:
                    coverage(
                        bill,
                        code,
                        "skipped",
                        f"Need {config.min_history} comparable prior bills ({config.baseline_mode}); have {len(prior)}.",
                        metric,
                    )
                else:
                    baseline = median(item[1] for item in prior)
                    if baseline <= 0:
                        coverage(bill, code, "skipped", "Percentage change from a zero baseline is undefined.", metric)
                    else:
                        pct = (value - baseline) / baseline * 100
                        flagged = (pct if increase_only else abs(pct)) > Fraction(str(threshold))
                        coverage(
                            bill,
                            code,
                            "flagged" if flagged else "checked",
                            f"Compared with {len(prior)} prior bills using {config.baseline_mode} median.",
                            metric,
                        )
                        if flagged:
                            impact = None
                            if metric == "total_due":
                                impact = decimal_value(max((value - baseline) * bill.days, 0))
                            elif metric == "effective_rate" and value > baseline:
                                impact = decimal_value((value - baseline) * Fraction(bill.electricity_kwh))
                            findings.append(
                                finding(
                                    bill,
                                    code,
                                    f"Unusual change in {metric.replace('_', ' ')}.",
                                    {
                                        "metric": metric,
                                        "current": decimal_value(value),
                                        "baseline_median": decimal_value(baseline),
                                        "percent_change": decimal_value(pct),
                                        "threshold_percent": threshold,
                                        "baseline_bill_count": len(prior),
                                        "billing_days": bill.days,
                                        "baseline_mode": config.baseline_mode,
                                        "normalization": "per kWh" if metric == "effective_rate" else "per billing day",
                                        "baseline_references": [old.reference for old, _ in prior],
                                    },
                                    "The change exceeds the configured threshold. Calendar-month matching, when selected, "
                                    "is not weather or occupancy normalization; legitimate operational or tariff changes remain possible.",
                                    "Compare source readings, operations, rate notices and seasonal conditions before escalating.",
                                    estimated_impact=impact,
                                    related_bill_ids=[old.id for old, _ in prior],
                                )
                            )
                history[key].append((bill, value))
                yearly = seasonal[(*key, bill.period_end.month)]
                yearly[bill.period_end.year] = (bill, value)
                while len(yearly) > config.min_history + 1:
                    del yearly[min(yearly)]
    for item in findings:
        item.input_digest = result.input_digest
    return result


def audit(bills: list[Bill], config: AuditConfig | None = None) -> list[Finding]:
    return analyze(bills, config).findings


def estimated_impact(bills: list[Bill], findings: list[Finding]) -> dict[str, Decimal]:
    by_id = {bill.id: bill for bill in bills}
    candidates: dict[str, Decimal] = {}
    for item in findings:
        if item.bill_id not in by_id or item.estimated_impact is None or item.review_status == "dismissed":
            continue
        candidates[item.bill_id] = max(candidates.get(item.bill_id, ZERO), item.estimated_impact)
    totals: dict[str, Decimal] = defaultdict(lambda: ZERO)
    for bill_id, amount in candidates.items():
        if by_id[bill_id].reliable("currency"):
            totals[by_id[bill_id].currency] += amount
    return dict(totals)

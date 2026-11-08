"""Self-contained downloadable reports with explicit scope and limitations."""

import csv
import html
import io
import json
import re
import textwrap
from dataclasses import asdict
from datetime import datetime, timezone

import pymupdf as fitz

from utilityaudit.audit import analyze, estimated_impact
from utilityaudit.models import AuditConfig, Bill, CheckCoverage, Finding, json_default, mask_account

DISCLAIMER = (
    "Potential financial impact is an unverified screening estimate, not confirmed "
    "overcharges, recoverable losses or recovered savings. Estimates use the largest "
    "positive candidate amount per bill, not the sum of overlapping findings. "
    "Bills without a reliable currency are excluded from monetary aggregates. "
    "A confirmed mathematical discrepancy only establishes disagreement in the "
    "supplied numbers; source completeness and provider liability remain unverified. "
    "No findings does not certify billing accuracy."
)
METHOD = (
    "Deterministic rules; exact decimal arithmetic. Historical anomalies require "
    "the configured number of earlier comparable, non-overlapping bills. "
    "Daily totals and usage are compared with median historical values. Effective "
    "electricity price is base + delivery + energy charges divided by kWh, only "
    "for explicitly electricity-only bills. Duplicate candidates are excluded "
    "from historical baselines; all overlap participants are excluded from trend "
    "checks. Optional same-calendar-month matching uses earlier years, not weather or occupancy modeling. "
    "Tariff correctness is not verified. Declared replacements and credit notes are excluded from trend baselines. "
    "Missing information can prevent checks from running. Human source verification "
    "is required before financial decisions."
)


def safe_cell(value: object) -> str:
    """Prevent spreadsheet formula execution even with leading whitespace."""
    text = "" if value is None else str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def export_csv(
    bills: list[Bill],
    findings: list[Finding],
    config: AuditConfig,
    *,
    coverage: list[CheckCoverage] | None = None,
    context: dict | None = None,
) -> bytes:
    coverage = analyze(bills, config).coverage if coverage is None else coverage
    context = context or {}
    fields = [
        "record_type",
        "reference",
        "customer",
        "provider",
        "account_masked",
        "currency",
        "period_start",
        "period_end",
        "invoice_date",
        "total_due",
        "code",
        "severity",
        "classification",
        "description",
        "evidence",
        "explanation",
        "recommended_action",
        "confidence",
        "verification_status",
        "estimated_impact",
        "review_status",
        "reviewed_by",
        "review_note",
        "details",
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()

    def write(row: dict) -> None:
        writer.writerow({name: safe_cell(value) for name, value in row.items()})

    write(
        {
            "record_type": "report",
            "description": "UtilityAudit AI audit report",
            "details": json.dumps(
                {
                    "generated_at": context.get("created_at", datetime.now(timezone.utc).isoformat()),
                    "bills_analyzed": len(bills),
                    "findings": len(findings),
                    "configuration": asdict(config),
                    "disclaimer": DISCLAIMER,
                    "method": METHOD,
                    "snapshot": context,
                }
            ),
        }
    )
    for currency, amount in estimated_impact(bills, findings).items():
        write(
            {
                "record_type": "impact_summary",
                "currency": currency,
                "estimated_impact": amount,
                "verification_status": "Unverified estimate, not savings",
                "explanation": "Largest candidate amount per bill; currencies are never combined.",
            }
        )
    for bill in bills:
        write(
            {
                "record_type": "bill",
                "reference": bill.reference,
                "customer": bill.customer_name,
                "provider": bill.provider,
                "account_masked": mask_account(bill.account_number),
                "currency": bill.currency,
                "period_start": bill.period_start,
                "period_end": bill.period_end,
                "invoice_date": bill.invoice_date,
                "total_due": bill.total_due,
                "verification_status": f"{sum(value == 'verified' for value in bill.quality.values())} fields human-verified; "
                "remaining populated fields are extracted input",
                "details": json.dumps(
                    {
                        "quality": bill.quality,
                        "warnings": bill.warnings,
                        "total_basis": bill.total_basis,
                        "utility_type": bill.utility_type,
                        "line_items_complete": bill.line_items_complete,
                        "electricity_kwh": bill.electricity_kwh,
                        "gas_therms": bill.gas_therms,
                        "water_usage": bill.water_usage,
                        "water_unit": bill.water_unit,
                        "version": bill.version,
                        "service_id": bill.service_id,
                        "meter_id": bill.meter_id,
                        "invoice_kind": bill.invoice_kind,
                    },
                    default=json_default,
                ),
            }
        )
    by_id = {bill.id: bill for bill in bills}
    for item in findings:
        if item.bill_id not in by_id:
            continue
        write(
            {
                "record_type": "finding",
                "reference": item.reference,
                "currency": by_id[item.bill_id].currency,
                "code": item.code,
                "severity": item.severity,
                "classification": item.classification,
                "description": item.description,
                "evidence": json.dumps(item.evidence, default=json_default),
                "explanation": item.explanation,
                "recommended_action": item.recommendation,
                "confidence": item.confidence,
                "verification_status": item.verification,
                "estimated_impact": item.estimated_impact,
                "review_status": item.review_status,
                "reviewed_by": item.reviewed_by,
                "review_note": item.review_note,
            }
        )
    for check in coverage:
        write(
            {
                "record_type": "coverage",
                "reference": check.reference,
                "code": check.check,
                "verification_status": check.status,
                "explanation": check.reason,
                "details": json.dumps({"metric": check.metric}),
            }
        )
    return output.getvalue().encode("utf-8-sig")


def escaped(value: object) -> str:
    return html.escape(str(value) if value is not None else "Missing", quote=True)


def evidence_html(evidence: dict) -> str:
    lines = []
    for key, value in evidence.items():
        text = json.dumps(value, default=json_default, ensure_ascii=False)
        # Bound unbroken runs so imported descriptions cannot exceed page width.
        text = re.sub(r"\S{65,}", lambda match: " ".join(textwrap.wrap(match[0], 64)), text)
        lines.append(f"<p><b>{escaped(key)}:</b> {escaped(text)}</p>")
    return "".join(lines)


def export_pdf(
    bills: list[Bill],
    findings: list[Finding],
    config: AuditConfig,
    *,
    coverage: list[CheckCoverage] | None = None,
    context: dict | None = None,
) -> bytes:
    coverage = analyze(bills, config).coverage if coverage is None else coverage
    context = context or {}
    generated = context.get("created_at", datetime.now(timezone.utc).isoformat())
    parts = [
        "<h1>UtilityAudit AI</h1><h2>Utility billing audit report</h2>",
        f"<p>Generated: {escaped(generated)}<br>Bills analyzed: {len(bills)} | Findings: {len(findings)}</p>",
        evidence_html(context),
        f'<div class="notice"><b>Important interpretation</b><p>{escaped(DISCLAIMER)}</p></div>',
        "<h2>Potential financial impact / estimate</h2>",
    ]
    impacts = estimated_impact(bills, findings)
    if impacts:
        for currency, amount in impacts.items():
            parts.append(f"<p><b>{escaped(currency)} {amount:,.2f}</b> - unverified, non-additive estimate</p>")
    else:
        parts.append("<p>No quantified estimate available. This does not establish that no error exists.</p>")
    parts.extend(
        [
            "<h2>Method and scope</h2>",
            f"<p>{escaped(METHOD)}</p>",
            "<h3>Rules used</h3>",
            evidence_html(asdict(config)),
            "<h2>Customer, account and bills analyzed</h2>",
        ]
    )
    for bill in bills:
        parts.extend(
            [
                f"<h3>{escaped(bill.reference)} / version {bill.version}</h3>",
                f"<p>Customer: {escaped(bill.customer_name)}<br>"
                f"Provider: {escaped(bill.provider)}<br>"
                f"Account: {escaped(mask_account(bill.account_number))}<br>"
                f"Billing period: {escaped(bill.period_start)} to {escaped(bill.period_end)}<br>"
                f"Invoice date: {escaped(bill.invoice_date)} | Due date: {escaped(bill.due_date)}<br>"
                f"Total: {escaped(bill.currency)} {escaped(bill.total_due)}<br>"
                f"Total basis: {escaped(bill.total_basis)} | Utility: {escaped(bill.utility_type)}<br>"
                f"Electricity: {escaped(bill.electricity_kwh)} kWh | Gas: {escaped(bill.gas_therms)} therms<br>"
                f"Water: {escaped(bill.water_usage)} {escaped(bill.water_unit)}<br>"
                f"Complete charge coverage declared: {bill.line_items_complete}<br>"
                f"Verification: {sum(value == 'verified' for value in bill.quality.values())} fields human-verified; "
                "all other populated fields are extracted input</p>",
                "<p>Missing or uncertain fields: "
                + escaped(
                    ", ".join(
                        f"{key} ({value})"
                        for key, value in bill.quality.items()
                        if value not in ("extracted", "verified")
                    )
                    or "None recorded"
                )
                + "</p>",
            ]
        )
        for warning in bill.warnings:
            parts.append(f"<p class='warning'>{escaped(warning)}</p>")
    parts.append("<h2>Findings and recommended actions</h2>")
    if not findings:
        parts.append("<p>No findings under the configured rules. Review data completeness and original documents.</p>")
    ids = {bill.id for bill in bills}
    for index, item in enumerate(findings, 1):
        if item.bill_id not in ids:
            continue
        parts.extend(
            [
                f'<h3 class="{escaped(item.severity)}">{index}. {escaped(item.description)}</h3>',
                f"<p>Reference: {escaped(item.reference)} | Severity: {escaped(item.severity)}<br>"
                f"Classification: {escaped(item.classification)}<br>"
                f"Confidence: {escaped(item.confidence)}<br>"
                f"Verification: {escaped(item.verification)}<br>"
                f"Review status: {escaped(item.review_status)} | Reviewer: {escaped(item.reviewed_by)}<br>"
                f"Review note: {escaped(item.review_note)}</p>",
                f"<p>{escaped(item.explanation)}</p>",
                "<h4>Supporting calculations and evidence</h4>",
                evidence_html(item.evidence),
                f"<p><b>Recommended action:</b> {escaped(item.recommendation)}</p>",
            ]
        )
        if item.estimated_impact is not None:
            parts.append(
                f"<p>Candidate impact: {item.estimated_impact:,.2f} in the invoice currency. "
                "Unverified estimate; do not sum overlapping findings.</p>"
            )
    parts.append(
        "<h2>Rule coverage</h2><p>Checked means the rule ran without a flag, not verified billing accuracy. "
        "A verified finding records a human review, not confirmed liability or recovery.</p>"
    )
    by_bill: dict[str, list[CheckCoverage]] = {}
    for check in coverage:
        by_bill.setdefault(check.reference, []).append(check)
    for reference, checks in by_bill.items():
        parts.append(f"<h3>{escaped(reference)}</h3>")
        for check in checks:
            parts.append(
                f"<p><b>{escaped(check.check)} {escaped(check.metric or '')}: {escaped(check.status)}</b> "
                f"{escaped(check.reason)}</p>"
            )
    story = fitz.Story(
        html="<html><body>" + "".join(parts) + "</body></html>",
        user_css="""
        body { font-family: sans-serif; font-size: 10pt; color: #172A43; }
        h1 { font-size: 28pt; color: #10243D; }
        h2 { font-size: 17pt; color: #17365B; margin-top: 20pt; }
        h3 { font-size: 12pt; margin-top: 16pt; }
        h4 { font-size: 10pt; }
        p { margin: 6pt 0; }
        .notice { background-color: #F0F4F8; padding: 12pt; }
        .high { color: #B3261E; }
        .warning { color: #9C5700; }
    """,
    )
    buffer = io.BytesIO()
    writer = fitz.DocumentWriter(buffer)
    page_rect = fitz.paper_rect("a4")
    content_rect = fitz.Rect(44, 44, page_rect.width - 44, page_rect.height - 48)
    try:
        more = True
        while more:
            device = writer.begin_page(page_rect)
            more, _ = story.place(content_rect)
            story.draw(device)
            writer.end_page()
    finally:
        writer.close()
    with fitz.open(stream=buffer.getvalue(), filetype="pdf") as document:
        document.set_metadata({"title": "UtilityAudit AI - Utility billing audit", "author": "UtilityAudit AI"})
        for index, page in enumerate(document):
            page.insert_text(
                (44, page.rect.height - 25),
                f"UtilityAudit AI | Unverified screening report | Page {index + 1} of {len(document)}",
                fontsize=8,
                color=(0.3, 0.35, 0.4),
            )
        return document.tobytes(garbage=4, deflate=True)

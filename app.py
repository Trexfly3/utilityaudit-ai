"""Streamlit adapter for the local UtilityAudit AI application."""

import hashlib
import json
import logging
import os
from dataclasses import asdict
from decimal import Decimal
from pathlib import Path

import pandas as pd
import pymupdf as fitz
import streamlit as st
from sqlalchemy.exc import SQLAlchemyError

from utilityaudit.audit import estimated_impact
from utilityaudit.auth import Auth
from utilityaudit.database import runtime_database
from utilityaudit.errors import ApplicationError, AuthenticationError
from utilityaudit.history import bill_table, monthly_history
from utilityaudit.ingestion import IngestionError
from utilityaudit.models import (
    EXTRACTED_FIELDS,
    AuditConfig,
    Bill,
    CheckCoverage,
    Finding,
    json_default,
    mask_account,
)
from utilityaudit.reports import DISCLAIMER
from utilityaudit.storage import DuplicateDocumentError, Repository

ROOT = Path(__file__).parent
PAGES = ("Dashboard", "Upload Bills", "Bill History", "Audit Findings", "Reports", "Settings")


def money(value: Decimal, currency: str) -> str:
    return f"{currency} {value:,.2f}"


@st.cache_resource(max_entries=4)
def app_database(configuration_fingerprint: str):
    return runtime_database()


def signed_in_database():
    configuration = {
        name: os.environ.get(name, "")
        for name in (
            "UTILITYAUDIT_DATA_DIR",
            "UTILITYAUDIT_DATABASE_URL",
            "UTILITYAUDIT_MODE",
            "UTILITYAUDIT_PUBLIC_URL",
            "UTILITYAUDIT_ENCRYPTION_KEYS",
        )
    }
    database = app_database(hashlib.sha256(json.dumps(configuration, sort_keys=True).encode()).hexdigest())
    auth = Auth(database)
    if "auth_token" not in st.session_state:
        st.title("Sign in to UtilityAudit AI")
        if not auth.has_users():
            st.info(
                "An operator must create the first owner from the terminal. There is no public signup or default password."
            )
            st.code(
                '.venv/bin/utilityaudit bootstrap --username YOUR_USERNAME --organization "YOUR ORGANIZATION"',
                language="bash",
            )
            st.caption(
                "The command prompts privately for your password. Existing v1 data requires an explicit legacy import."
            )
            st.stop()
        with st.form("login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in", type="primary")
        if submitted:
            try:
                token = auth.login(username, password)
            except AuthenticationError as exc:
                st.error(str(exc))
            else:
                st.session_state.clear()
                st.session_state["auth_token"] = token
                st.rerun()
        st.stop()
    try:
        identity = auth.authenticate(st.session_state["auth_token"])
    except AuthenticationError:
        st.session_state.clear()
        st.rerun()
    return database, auth, identity


def clear_workspace_state() -> None:
    for key in list(st.session_state):
        if key not in ("auth_token", "organization_choice"):
            del st.session_state[key]


def render_findings(findings: list[Finding], repo: Repository | None = None) -> None:
    if not findings:
        st.info("No findings under the current rules. This is not a certification of billing accuracy.")
    if len(findings) > 50:
        page = st.number_input("Findings page", min_value=1, max_value=(len(findings) + 49) // 50, step=1)
        st.caption(f"{len(findings)} findings; showing up to 50 at a time.")
        findings = findings[(page - 1) * 50 : page * 50]
    for item in findings:
        with st.expander(f"{item.severity.upper()} | {item.reference} | {item.description}"):
            message = {"high": st.error, "warning": st.warning, "info": st.info}[item.severity]
            message(item.classification)
            st.write(item.explanation)
            st.caption(f"Confidence: {item.confidence} | {item.verification}")
            st.write(f"**Review:** {item.review_status}")
            if item.reviewed_by:
                st.caption(f"Reviewed by {item.reviewed_by} at {item.reviewed_at}")
                st.text(item.review_note)
            st.json(json.loads(json.dumps(item.evidence, default=json_default)))
            st.write("**Recommended action:**", item.recommendation)
            if item.estimated_impact is not None:
                st.caption(
                    f"Candidate impact: {item.estimated_impact:,.2f} in the invoice currency. "
                    "Unverified estimate; findings must not be added together."
                )
            if repo is not None and repo.role in ("owner", "auditor"):
                with st.form(f"review-{repo.organization_id}-{item.key}"):
                    status = st.selectbox(
                        "Review decision",
                        ["unresolved", "verified", "dismissed"],
                        index=["unresolved", "verified", "dismissed"].index(item.review_status),
                    )
                    note = st.text_area("Source evidence and reasoning", value=item.review_note, max_chars=2000)
                    st.caption(
                        "Verified means you checked this finding against evidence, not that an overcharge or recovery is confirmed."
                    )
                    if st.form_submit_button("Save review"):
                        repo.review(item.key, status, note, expected_version=item.review_version)
                        st.session_state["notice"] = "Review recorded. Earlier decisions remain in the audit history."
                        st.rerun()


def render_coverage(coverage: list[CheckCoverage]) -> None:
    with st.expander("Rule coverage: checked, flagged and skipped"):
        st.caption("A check that ran without a flag is not a certification. Skipped rules provide no assurance.")
        if coverage:
            frame = pd.DataFrame([asdict(item) for item in coverage]).drop(columns=["bill_id"])
            st.dataframe(frame, hide_index=True, width="stretch")


def render_trends(bills: list[Bill]) -> None:
    frame = monthly_history(bills)
    if frame.empty:
        st.info("Add bills with reliable dates and explicit currencies to display trends.")
        return
    st.caption(
        "Current-charge totals by invoice month (period-end fallback). Duplicate candidates, "
        "superseded bills and credit notes excluded. Amounts due with unknown current charges remain missing. "
        "Check coverage counts for partial months; usage is not prorated."
    )
    for currency, group in frame.groupby("Currency"):
        st.subheader(f"Monthly history / {currency}")
        indexed = group.set_index("Month")
        left, right = st.columns(2)
        with left:
            st.caption("Billed amounts, not payment records")
            st.bar_chart(indexed[["Spending"]], color="#17365B")
        with right:
            st.caption("Electricity usage / kWh")
            st.line_chart(indexed[["Electricity kWh"]], color="#16734B")
        if indexed["Gas therms"].notna().any():
            st.line_chart(indexed[["Gas therms"]], color="#C77813")
        st.dataframe(group, hide_index=True, width="stretch")
    st.caption(
        "Average electricity price is usage-weighted: explicit electricity-only base, "
        "delivery and energy charges / kWh. It excludes taxes and fees and is not a tariff rate. "
        "Monthly percentage changes are shown only for consecutive months with positive baselines."
    )


def dashboard(
    repo: Repository, bills: list[Bill], findings: list[Finding], config: AuditConfig, coverage: list[CheckCoverage]
) -> None:
    st.title("Your utility audit, at a glance")
    st.write("Evidence first. Clear next steps. No assumed savings.")
    anomalies = [item for item in findings if item.code != "missing_information" and item.review_status != "dismissed"]
    first, second, third = st.columns(3)
    first.metric("Bills analyzed", len(bills))
    second.metric("Active anomalies", len(anomalies))
    totals = estimated_impact(bills, findings)
    if len(totals) == 1:
        currency, amount = next(iter(totals.items()))
        third.metric("Suspicious amount / estimate", money(amount, currency))
    elif totals:
        third.metric("Suspicious amount / estimate", "Multiple currencies")
        for currency, amount in totals.items():
            st.write(money(amount, currency))
    else:
        third.metric("Suspicious amount / estimate", "No quantified estimate")
    st.warning("Candidate amounts are unverified screening estimates, not confirmed overcharges or recovered savings.")
    st.caption(
        "Estimate uses the largest positive candidate amount per bill to reduce double counting. "
        "Bills without a reliable currency are excluded. "
        "Findings without a defensible estimate are not valued at zero."
    )
    st.write(f"Data-quality findings: {sum(item.code == 'missing_information' for item in findings)}")
    if st.button("Run audit", type="primary", disabled=not bills or repo.role == "viewer" or len(bills) > 500):
        repo.run_audit([bill.id for bill in bills])
        st.success("Immutable report snapshot recorded. Results still require source verification.")
    if len(bills) > 500:
        st.info("Narrow the account scope or select up to 500 bills on Reports to record a snapshot.")
    render_coverage(coverage)
    render_trends(bills)
    st.subheader("Recent audit activity")
    activity = repo.recent_runs()
    if activity:
        st.dataframe(pd.DataFrame(activity), hide_index=True, width="stretch")
        st.caption(
            "Organization-scoped, immutable report snapshots. Deleting source data purges dependent report contents."
        )
    else:
        st.info("No recorded audits yet. Upload bills or run an audit to create activity.")


def upload_page(repo: Repository, config: AuditConfig) -> None:
    st.title("Upload bills")
    st.write("Import text PDFs or structured CSV files. Documents stay on this machine.")
    st.info(
        "PDF extraction is label-based, not AI or OCR. Review field status after import. "
        "For unsupported layouts, use the CSV schema in README.md."
    )
    st.download_button(
        "Download synthetic CSV example", (ROOT / "samples/bills.csv").read_bytes(), "synthetic-bills.csv", "text/csv"
    )
    files = st.file_uploader(
        "Utility documents",
        type=["pdf", "csv"],
        accept_multiple_files=True,
        key=f"uploads-{repo.organization_id}",
        disabled=repo.role == "viewer",
    )
    if st.button("Import selected documents", type="primary", disabled=not files or repo.role == "viewer"):
        if len(files) > 20 or sum(file.size for file in files) > 50 * 1024 * 1024:
            st.error("Import at most 20 files and 50 MiB per batch. Each file must be at most 10 MiB.")
        else:
            imported = 0
            for file in files:
                try:
                    count = repo.import_document(file.name, file.getvalue())
                except (IngestionError, DuplicateDocumentError, ValueError) as exc:
                    st.text(file.name)
                    st.error(str(exc))
                else:
                    imported += count
                    st.success(f"{file.name}: imported {count} bill(s). Review extraction before relying on findings.")
            if imported:
                st.info(
                    "Import activity recorded. Review extracted values and rule coverage before generating a report snapshot."
                )
    st.subheader("Document library")
    documents = repo.documents()
    if not documents:
        st.info("No uploaded documents.")
        return
    by_id = {document["id"]: document for document in documents}
    selected = st.selectbox("Document", list(by_id), format_func=lambda key: f"{by_id[key]['name']} / {key[:8]}")
    document = by_id[selected]
    st.caption(f"Uploaded {document['uploaded_at']} | {document['bytes']:,} bytes")
    document_bills = [bill for bill in repo.bills() if bill.document_id == selected]
    st.dataframe(bill_table(document_bills), hide_index=True, width="stretch")
    show_original = st.checkbox(
        "Show original document controls (contains unmasked personal information)",
        key=f"original-{selected}",
        disabled=repo.role == "viewer",
    )
    if show_original:
        data = repo.document_content(selected)
        is_pdf = document["name"].lower().endswith(".pdf")
        st.download_button(
            "Download original document", data, document["name"], "application/pdf" if is_pdf else "text/csv"
        )
        if is_pdf:
            with fitz.open(stream=data, filetype="pdf") as pdf:
                page_number = st.number_input("Preview page", min_value=1, max_value=len(pdf), step=1)
                page = pdf[int(page_number) - 1]
                scale = min(1.5, 1400 / max(page.rect.width, page.rect.height))
                st.image(
                    page.get_pixmap(matrix=fitz.Matrix(scale, scale)).tobytes("png"),
                    caption=f"Original document / page {page_number}",
                )
        else:
            st.text_area("Original CSV contents", data.decode("utf-8-sig"), height=240, disabled=True)
    confirmed = st.checkbox(
        "Permanently remove this document and its extracted bills",
        key=f"delete-{selected}",
        disabled=repo.role != "owner",
    )
    if st.button("Remove document", disabled=not confirmed or repo.role != "owner"):
        repo.delete_document(selected)
        st.session_state["notice"] = (
            "Document, revisions, reviews and dependent report contents removed. External backups are not affected."
        )
        st.rerun()


def history_page(repo: Repository, bills: list[Bill], findings: list[Finding]) -> None:
    st.title("Bill history")
    if not bills:
        st.info("Upload bills to explore your billing history.")
        return
    st.dataframe(bill_table(bills), hide_index=True, width="stretch")
    selected = st.selectbox(
        "Inspect extracted bill", range(len(bills)), format_func=lambda index: bills[index].reference
    )
    bill = bills[selected]
    st.write("Customer:", bill.customer_name or "Missing")
    rows = []
    for name in EXTRACTED_FIELDS:
        value = getattr(bill, name)
        if name == "account_number":
            value = mask_account(value)
        if name in ("invoice_number", "supersedes_invoice_number"):
            value = "Present (see original document)" if value else None
        rows.append(
            {
                "Field": name,
                "Value": str(value) if value is not None else "Missing",
                "Status": bill.quality.get(name, "missing"),
            }
        )
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    if bill.warnings:
        st.caption("Original extraction notes (retained even after correction)")
    for warning in bill.warnings:
        st.warning(warning)
    if bill.line_items:
        st.dataframe(
            pd.DataFrame([asdict(item) for item in bill.line_items]).astype(str), hide_index=True, width="stretch"
        )
    st.caption(
        f"Complete line items declared: {'yes' if bill.line_items_complete else 'no'}. "
        "Extraction status is not human verification."
    )
    if repo.role in ("owner", "auditor") and st.checkbox(
        "Open sensitive source review", key=f"source-review-{bill.id}"
    ):
        with st.expander("Review source evidence and correct this bill (sensitive information)"):
            field_name = st.selectbox(
                "Field to correct or verify",
                [*EXTRACTED_FIELDS, "line_items", "line_items_complete"],
                key=f"field-{bill.id}",
            )
            source = bill.provenance.get(field_name, [])
            st.json(
                source if source else {"status": "No extraction evidence; cite the original source when correcting."}
            )
            data = repo.document_content(bill.document_id)
            source_page = None
            if data.startswith(b"%PDF-"):
                with fitz.open(stream=data, filetype="pdf") as document:
                    source_page = st.number_input(
                        "Source page for this correction",
                        min_value=1,
                        max_value=len(document),
                        value=next((item["page"] for item in reversed(source) if item.get("page")), 1),
                    )
                    page = document[source_page - 1]
                    scale = min(1.5, 1200 / max(page.rect.width, page.rect.height))
                    st.image(page.get_pixmap(matrix=fitz.Matrix(scale, scale)).tobytes("png"))
            if field_name == "line_items":
                value = json.dumps([asdict(item) for item in bill.line_items], default=json_default)
            elif field_name == "line_items_complete":
                value = "true" if bill.line_items_complete else "false"
            else:
                value = str(getattr(bill, field_name)) if getattr(bill, field_name) is not None else ""
            with st.form(f"correction-{bill.id}-{bill.version}-{field_name}"):
                corrected = st.text_area("Corrected value (blank clears it)", value=value)
                reason = st.text_area("Correction reason and source evidence", max_chars=2000)
                confirmed = st.checkbox("I checked this value against the original source")
                if st.form_submit_button("Save correction / verification"):
                    if not confirmed:
                        st.error("Review the original source and confirm before saving.")
                    else:
                        repo.correct(
                            bill.id,
                            {field_name: corrected},
                            [],
                            expected_version=bill.version,
                            reason=reason,
                            source_page=source_page,
                        )
                        st.session_state["notice"] = (
                            "Versioned correction saved. Findings recalculated; stale review decisions no longer apply."
                        )
                        st.rerun()
            for revision in repo.revision_history(bill.id):
                st.write(f"Version {revision['version']} / {revision['actor']} / {revision['created_at']}")
                st.text(revision["reason"])
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "Field": name,
                                "Before": str(revision["before"].get(name)),
                                "After": str(revision["after"].get(name)),
                            }
                            for name in revision["fields"]
                        ]
                    ),
                    hide_index=True,
                    width="stretch",
                )
            st.subheader("Finding review history")
            reviews = repo.review_history(bill.id)
            if reviews:
                st.dataframe(pd.DataFrame(reviews), hide_index=True, width="stretch")
                st.caption("Historical finding keys may no longer apply after data or rule changes.")
    render_trends(bills)
    st.subheader("Historical anomalies")
    render_findings([item for item in findings if item.code in ("bill_increase", "usage_change", "rate_change")])


def findings_page(repo: Repository, findings: list[Finding], coverage: list[CheckCoverage]) -> None:
    st.title("Audit findings")
    st.caption("High severity indicates investigation priority, not proof of an overcharge.")
    selected = st.multiselect("Severity", ["high", "warning", "info"], default=["high", "warning", "info"])
    decisions = st.multiselect(
        "Review status", ["unresolved", "verified", "dismissed"], default=["unresolved", "verified"]
    )
    render_coverage(coverage)
    render_findings([item for item in findings if item.severity in selected and item.review_status in decisions], repo)


def settings_page(repo: Repository, config: AuditConfig) -> None:
    st.title("Settings")
    st.subheader("Conservative audit thresholds")
    with st.form("audit_settings"):
        bill_pct = st.number_input(
            "Bill increase threshold (%)", min_value=1.0, max_value=1000.0, value=float(config.bill_increase_pct)
        )
        usage_pct = st.number_input(
            "Usage change threshold (%)", min_value=1.0, max_value=1000.0, value=float(config.usage_change_pct)
        )
        rate_pct = st.number_input(
            "Effective price change threshold (%)", min_value=1.0, max_value=1000.0, value=float(config.rate_change_pct)
        )
        baseline = st.number_input("Prior bills required", min_value=3, max_value=24, value=config.min_history)
        tolerance = st.number_input(
            "Arithmetic tolerance (invoice currency)",
            min_value=0.0,
            max_value=1.0,
            value=float(config.arithmetic_tolerance),
            step=0.01,
            format="%.2f",
        )
        baseline_mode = st.selectbox(
            "Baseline comparison", ["recent", "same_month"], index=["recent", "same_month"].index(config.baseline_mode)
        )
        st.caption("Same-month mode requires prior bills from at least three earlier years in that calendar month.")
        if st.form_submit_button("Save thresholds", disabled=repo.role != "owner"):
            updated = AuditConfig(bill_pct, usage_pct, rate_pct, int(baseline), str(tolerance), baseline_mode)
            repo.save_config(updated)
            st.success("Thresholds saved. Subsequent views and exports use the updated rules.")
    st.subheader("Privacy and operating limits")
    st.warning(
        "Authentication and organization boundaries are implemented, but public deployment still requires "
        "TLS, controlled infrastructure, restore drills and an independent security assessment."
    )
    st.write(
        "Document and bill payloads, corrections, reviews and reports are encrypted. The local key is stored "
        "separately with restrictive permissions; it does not protect against a compromised host. "
        "Back up keys separately. Normal views mask account identifiers."
    )
    st.write(
        "Weather and tariff correctness are not modeled. Scanned PDFs require external OCR "
        "or manual structured CSV entry. This version does not submit disputes or verify recoverable savings."
    )
    if repo.role == "owner":
        st.subheader("Organization membership")
        with st.form("membership"):
            username = st.text_input("Existing username")
            role = st.selectbox("Role", ["viewer", "auditor", "owner", "remove"])
            if st.form_submit_button("Update membership"):
                Auth(repo.db).set_membership(
                    repo.identity, repo.organization_id, username, None if role == "remove" else role
                )
                st.success(
                    "Membership updated. An operator must create users through the CLI; there is no public signup."
                )
        with st.form("retention"):
            days = st.number_input(
                "Retention days (0 disables expiry)", min_value=0, max_value=3650, value=repo.retention_days() or 0
            )
            if st.form_submit_button("Save retention policy"):
                repo.set_retention(days or None)
                st.success("Policy saved. Purging is a separate, explicit operator command.")
        st.caption(
            f"Documents currently eligible for purge: {len(repo.purge_expired())}. "
            "Dependent report contents and sensitive revision/review data are purged with documents."
        )
    with st.form("change_password"):
        st.subheader("Change password")
        old = st.text_input("Current password", type="password")
        new = st.text_input("New password (12-128 characters)", type="password")
        if st.form_submit_button("Change password and sign out"):
            Auth(repo.db).change_password(repo.identity, old, new)
            st.session_state.clear()
            st.rerun()
    st.subheader("Organization audit trail")
    st.dataframe(pd.DataFrame(repo.activity()), hide_index=True, width="stretch")


def reports_page(repo: Repository, bills: list[Bill], findings: list[Finding], config: AuditConfig) -> None:
    st.title("Reports")
    st.warning(DISCLAIMER)
    st.caption(
        "Exports use the current account/currency scope and thresholds. "
        "Accounts are masked; customer names and financial information remain sensitive."
    )
    selected_ids = [bill.id for bill in bills]
    if len(bills) > 500:
        by_id = {bill.id: bill for bill in bills}
        selected_ids = st.multiselect(
            "Select up to 500 bills", list(by_id), format_func=lambda key: by_id[key].reference, max_selections=500
        )
    if st.button("Generate downloadable reports", type="primary", disabled=not selected_ids or repo.role == "viewer"):
        with st.spinner("Building an immutable report snapshot..."):
            st.session_state["latest_run"] = repo.run_audit(selected_ids)
    runs = [run for run in repo.recent_runs() if not run["purged_at"]]
    if runs:
        ids = [run["id"] for run in runs]
        selected_run = st.selectbox(
            "Saved report snapshot",
            ids,
            format_func=lambda key: next(
                f"{run['created_at']} / {run['bill_count']} bills / {key[:8]}" for run in runs if run["id"] == key
            ),
        )
        st.download_button(
            "Download PDF report",
            repo.report(selected_run, "pdf"),
            "utility-audit-report.pdf",
            "application/pdf",
            on_click="ignore",
        )
        st.download_button(
            "Download CSV report",
            repo.report(selected_run, "csv"),
            "utility-audit-report.csv",
            "text/csv",
            on_click="ignore",
        )
        st.caption(
            "Saved bytes do not change after corrections or reviews. Generate a new snapshot for updated results."
        )
    elif not bills:
        st.info("Upload bills to generate a report.")
    st.write("Current audit scope")
    st.dataframe(bill_table(bills), hide_index=True, width="stretch")
    render_findings(findings)


def main() -> None:
    st.set_page_config(page_title="UtilityAudit AI", page_icon="⚡", layout="wide")
    st.markdown(
        """
    <style>
    [data-testid="stSidebar"] {background: #10243D;}
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"],
    [data-testid="stSidebar"] label {color: #FFFFFF;}
    [data-testid="stMetric"] {background: #F0F4F8; border: 1px solid #DCE4EC;
        border-radius: 12px; padding: 18px;}
    h1, h2, h3 {letter-spacing: -0.02em;}
    .block-container {padding-top: 2rem; max-width: 1440px;}
    </style>
    """,
        unsafe_allow_html=True,
    )
    database, auth, identity = signed_in_database()
    with st.sidebar:
        st.title("UtilityAudit AI")
        st.caption(f"Signed in as {identity.username}")
        if st.button("Sign out"):
            auth.logout(st.session_state["auth_token"])
            st.session_state.clear()
            st.rerun()
        organizations = auth.organizations(identity)
        if not organizations:
            st.info("No organization memberships. Ask an owner to add your username, or create an organization.")
        with st.expander("Create an organization"):
            with st.form("new_organization"):
                name = st.text_input("Organization name")
                if st.form_submit_button("Create organization"):
                    auth.create_organization(identity, name)
                    clear_workspace_state()
                    st.rerun()
        if not organizations:
            st.stop()
        by_id = {item["id"]: item for item in organizations}
        organization_id = st.selectbox(
            "Organization",
            list(by_id),
            key="organization_choice",
            format_func=lambda key: by_id[key]["name"],
            on_change=clear_workspace_state,
        )
        repo = Repository(database, identity, organization_id)
        st.caption(f"Role: {repo.role}")
        all_bills, result, config = repo.analysis()
        all_findings = result.findings
        page = st.radio("Workspace", PAGES, label_visibility="collapsed")
        st.divider()
        st.markdown("**Analysis scope**")
        currency_options = ["All currencies"] + sorted({bill.currency or "Unknown currency" for bill in all_bills})
        currency = st.selectbox("Currency", currency_options)
        # Opaque indices keep full account numbers out of widget labels.
        accounts = sorted({(bill.provider or "", bill.account_number or "") for bill in all_bills})
        account_index = st.selectbox(
            "Account",
            [-1] + list(range(len(accounts))),
            format_func=lambda index: (
                "All accounts"
                if index == -1
                else f"{index + 1}. {accounts[index][0]} / {mask_account(accounts[index][1])}"
            ),
        )
        st.caption("Estimates are not recovered savings.")
    bills = [
        bill
        for bill in all_bills
        if (currency == "All currencies" or (bill.currency or "Unknown currency") == currency)
        and (account_index == -1 or (bill.provider or "", bill.account_number or "") == accounts[account_index])
    ]
    ids = {bill.id for bill in bills}
    findings = [item for item in all_findings if item.bill_id in ids]
    coverage = [item for item in result.coverage if item.bill_id in ids]
    if "notice" in st.session_state:
        st.success(st.session_state.pop("notice"))
    if page == "Dashboard":
        dashboard(repo, bills, findings, config, coverage)
    elif page == "Upload Bills":
        upload_page(repo, config)
    elif page == "Bill History":
        history_page(repo, bills, findings)
    elif page == "Audit Findings":
        findings_page(repo, findings, coverage)
    elif page == "Reports":
        reports_page(repo, bills, findings, config)
    elif page == "Settings":
        settings_page(repo, config)
    st.divider()
    st.caption("UtilityAudit AI | Deterministic analysis | Verify the source before making financial decisions")


if __name__ == "__main__":
    try:
        main()
    except (ApplicationError, ValueError) as exc:
        st.error(str(exc))
        st.stop()
    except (SQLAlchemyError, OSError) as exc:
        logging.getLogger(__name__).error("Application storage failure: %s", type(exc).__name__)
        st.error(
            "Local data could not be read or saved. Check storage permissions, available disk space, "
            "and database integrity. No successful operation is implied."
        )
        st.stop()

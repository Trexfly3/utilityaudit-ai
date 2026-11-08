"""Ground-truth evaluation without shipping or transmitting customer documents."""

import json
from pathlib import Path

from utilityaudit.audit import analyze
from utilityaudit.ingestion import ingest
from utilityaudit.models import EXTRACTED_FIELDS, AuditConfig


def evaluate(manifest_path: Path) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    kind = manifest.get("dataset_kind")
    if kind not in ("synthetic", "authorized_real"):
        raise ValueError("Declare dataset_kind as synthetic or authorized_real.")
    if kind == "authorized_real" and manifest.get("permission_confirmed") is not True:
        raise ValueError("Confirm permission before processing real customer documents.")
    files = manifest.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= 100:
        raise ValueError("Evaluation requires 1 to 100 input files.")
    bills = []
    for entry in files:
        path = (manifest_path.parent / entry).resolve()
        if not path.is_relative_to(manifest_path.parent.resolve()):
            raise ValueError("Evaluation inputs must stay inside the dataset directory.")
        bills.extend(ingest(path.name, path.read_bytes())[2])
    if len(bills) > 5000:
        raise ValueError("Evaluation is limited to 5,000 bills.")
    result = analyze(bills, AuditConfig(**manifest.get("configuration", {})))
    indexes = {bill.id: index for index, bill in enumerate(bills)}
    matched, evaluated, mismatches = 0, 0, []
    for truth in manifest.get("fields", []):
        index, name = truth["bill_index"], truth["field"]
        if name not in EXTRACTED_FIELDS or type(index) is not int or not 0 <= index < len(bills):
            raise ValueError("Ground truth references an unknown bill or field.")
        actual = getattr(bills[index], name)
        actual = str(actual) if actual is not None else None
        evaluated += 1
        if actual == truth["value"] and bills[index].quality.get(name) == truth["status"]:
            matched += 1
        else:
            mismatches.append({"bill_index": index, "field": name})
    expected = {(item["bill_index"], item["code"]) for item in manifest.get("findings", [])}
    actual = {(indexes[item.bill_id], item.code) for item in result.findings}
    true_positive, false_positive, false_negative = (
        len(expected & actual),
        len(actual - expected),
        len(expected - actual),
    )
    return {
        "dataset_kind": kind,
        "validation_scope": "Synthetic regression only; not real-bill accuracy."
        if kind == "synthetic"
        else "Permissioned sample evaluation; not a guarantee for other providers or customers.",
        "bills": len(bills),
        "fields_evaluated": evaluated,
        "fields_correct": matched,
        "field_accuracy": matched / evaluated if evaluated else None,
        "field_mismatches": mismatches,
        "finding_true_positives": true_positive,
        "finding_false_positives": false_positive,
        "finding_false_negatives": false_negative,
        "finding_precision": true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else None,
        "finding_recall": true_positive / (true_positive + false_negative) if true_positive + false_negative else None,
        "skipped_checks": sum(item.status == "skipped" for item in result.coverage),
    }

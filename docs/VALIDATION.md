# Accuracy evaluation and controlled pilots

## Ground truth, not a demo score

`samples/ground_truth.json` evaluates twelve field assertions and four expected
findings on a synthetic CSV. It is a regression fixture, **not evidence of
real-provider extraction accuracy**. Automated PDF tests also use synthetic
documents. No customer data was obtained, uploaded to an external service or
used to claim production accuracy.

Run `utilityaudit evaluate path/to/ground_truth.json`. Inputs stay local.
The manifest declares `dataset_kind` as `synthetic` or `authorized_real`; real
datasets additionally require `permission_confirmed: true`. That is an operator
attestation, not automatic verification of consent.

Files must be within the manifest directory. Keep real datasets under the ignored
`validation-data/` directory, encrypt/protect the host, and remove unnecessary
identifiers. The manifest itself may contain sensitive expected values. Do not
commit either documents or ground truth.

The schema is illustrated by the shipped manifest:
- `files`: input PDF/CSV filenames, in bill ordering.
- `fields`: zero-based `bill_index`, supported `field`, canonical string or null
  `value`, and extraction `status`.
- `findings`: expected `bill_index` and rule `code`.
- `configuration`: optional explicit audit thresholds/baseline mode.

Metrics report exact field matches (including missing/uncertain status), finding
precision/recall, false positives/negatives and skipped rules. A metric without an
evaluated denominator is null, not an invented perfect score. Evaluation compares
rule codes per bill; multi-metric usage checks share a code, so review their
evidence separately when measuring metric-specific performance.

## Build a permissioned representative set

Cover electricity, gas and water providers; varied layouts; credits; previous
balances and payment postings; revised invoices; duplicate imports versus actual
duplicate payments; multiple meters; seasonal load; unusual but legitimate
tariff changes; malformed/scanned PDFs; and incomplete records.

Have qualified auditors label amounts, units, dates and findings independently
from the application output. Record disagreements and adjudication. Keep separate
development and holdout sets to avoid tuning thresholds to the same examples used
to advertise accuracy. Report provider/layout-specific sample counts and results,
not just a pooled percentage.

Define acceptable false-positive and missed-error rates with the customer.
Track skipped checks and manual corrections so lower anomaly counts cannot hide
failed extraction. Require source verification for decisions with financial
consequences. Arithmetic consistency alone does not validate tariff entitlement.

## Pilot acceptance

Use a limited, permissioned organization with named owners/auditors, documented
retention, tested backup recovery and no autonomous disputes. Auditors should
review all pilot findings, a sample of unflagged bills, and every skipped material
check. Record correction frequency, review time, disagreement reasons and actual
provider/payment evidence separately from estimated impact.

The application can store reviewer decisions and immutable snapshots. It does
not yet run a customer pilot, acquire permissions, verify legal claims, integrate
payment/refund records, or establish that a charge was recovered. Those are
external activities, not functionality to simulate.

# Information is shared with designated stakeholders during incidents

`NIST-CSF-2-RS.CO-03` · framework **nist-csf-2** · severity **medium** · Respond

## What this control checks

NIST CSF 2.0 RS.CO-03 requires that information is shared with
designated internal and external stakeholders during an incident.
Concord reads a cosigned attestation that records the information-
sharing protocols, the designated recipients authorized to receive
incident information, and the approval process that gates what is
shared and with whom.

## Why it matters

Sharing accurate, appropriately-scoped information keeps responders,
leadership, and external partners aligned, while an approval gate
prevents premature or over-broad disclosure that could harm the
investigation or the organization. Attesting to sharing protocols,
designated recipients, and an approval process — reviewed at least
annually — demonstrates information flows are deliberate and controlled
rather than ad hoc.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-information-sharing attestation collected
- attestation kind is <value>, expected <value>
- incident-information-sharing attestation cosign signature did not verify
- incident-information-sharing attestation missing required field: <value>
- incident-information-sharing attestation names zero designated recipients
- incident-information-sharing protocol last reviewed <value> — older than <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1w**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.CO-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.CO-03"]
  nist_800_53: ["IR-6", "IR-4"]
  iso27001: ["A.5.5", "A.5.6"]
  soc2: ["CC2.2", "CC2.3"]
```

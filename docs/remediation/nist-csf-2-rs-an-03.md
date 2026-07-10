# Analysis is performed to establish what has taken place during an incident

`NIST-CSF-2-RS.AN-03` · framework **nist-csf-2** · severity **high** · Respond

## What this control checks

NIST CSF 2.0 RS.AN-03 requires that analysis is performed to establish
what has taken place during an incident and the root cause of that
incident. Concord reads a cosigned attestation that records the
organization's incident-analysis capability: the analysis methodology
applied, the forensic capability available, and the documentation
standard used to capture findings.

## Why it matters

Without a repeatable analysis capability, responders cannot reliably
determine scope, root cause, or the actions needed to contain and
eradicate an incident. Attesting to a documented methodology, forensic
readiness, and a documentation standard — reviewed at least annually —
demonstrates the organization can establish what happened rather than
guessing. The attestation is cosigned so the evidence is tamper-evident.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-analysis attestation collected
- attestation kind is <value>, expected <value>
- incident-analysis attestation cosign signature did not verify
- incident-analysis attestation missing required field: <value>
- incident-analysis attestation defines zero analysis methodologies
- incident-analysis capability last reviewed <value> — older than <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1w**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.AN-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.AN-03"]
  nist_800_53: ["IR-4", "AU-6", "IR-5"]
  iso27001: ["A.5.25", "A.5.26"]
  soc2: ["CC7.3"]
```

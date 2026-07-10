# Cybersecurity supply chain risk management program is established

`NIST-CSF-2-GV.SC-01` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.SC-01 requires a cybersecurity supply chain risk
management (C-SCRM) program to be established, and its objectives,
stakeholders, and management processes to be agreed by organizational
stakeholders. Concord reads a cosigned C-SCRM program attestation that
records the program scope, the roles accountable for it, the
governance forum overseeing it, and the date it was last reviewed.

## Why it matters

GV.SC-01 is the anchor control for the entire GV.SC category; every
other supply-chain finding assumes a C-SCRM program exists. Auditors
check that the program has an agreed scope, named owners, and a
governance cadence rather than being ad hoc. The attestation captures
that structure and forces annual re-review.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no C-SCRM program attestation collected
- attestation kind is <value>, expected <value>
- C-SCRM program attestation missing required field: <value>
- C-SCRM program has no accountable roles assigned
- C-SCRM program attestation cosign signature did not verify
- C-SCRM program has not been reviewed in the last 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1w**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.SC-01
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.SC-01"
  nist_800_53:
  - "SR-1"
  - "SR-2"
  - "PM-30"
  iso27001:
  - "A.5.19"
  - "A.5.21"
  soc2:
  - "CC9.2"
```

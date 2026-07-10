# Adequate resources are allocated commensurate with cybersecurity strategy

`NIST-CSF-2-GV.RR-03` · framework **nist-csf-2** · severity **medium** · Govern

## What this control checks

NIST CSF 2.0 GV.RR-03 requires adequate resources — budget, staffing,
and tooling — to be allocated commensurate with the organization's
cybersecurity risk strategy and role expectations. Concord reads a
cosigned resource-allocation attestation that records the approved
budget, the staffing plan, the tooling investment, and the date the
allocation was last reviewed.

## Why it matters

A cybersecurity strategy that is not funded is a paper exercise.
Auditors use GV.RR-03 to confirm that leadership backed the strategy
with real money, headcount, and tooling. The attestation makes the
committed resources explicit and requires the allocation to be
reviewed at least annually so it keeps pace with the strategy.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no resource-allocation attestation collected
- attestation kind is <value>, expected <value>
- resource-allocation attestation missing required field: <value>
- resource-allocation attestation lists zero staffing commitments
- resource-allocation attestation cosign signature did not verify
- resource allocation has not been reviewed in the last 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.RR-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.RR-03"
  nist_800_53:
  - "SA-2"
  - "PM-3"
  iso27001:
  - "A.5.4"
  soc2:
  - "CC1.4"
```

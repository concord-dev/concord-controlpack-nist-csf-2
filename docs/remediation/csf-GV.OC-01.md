# Organizational mission and stakeholders documented and current

`NIST-CSF-2-GV.OC-01` · framework **nist-csf-2** · severity **medium** · Govern

## What this control checks

NIST CSF 2.0 GV.OC-01 requires the organizational mission to be
understood and to inform cybersecurity risk management. Concord
reads a signed mission-and-context attestation.

## Why it matters

GV.OC anchors why cybersecurity decisions are being made. Without
a documented mission, the rest of GV is unanchored.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no org-mission attestation collected
- attestation kind is <value>, expected "org_mission_context"
- attestation missing required field: <value>
- mission attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.OC-01
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["GV.OC-01"]
  iso27001: ["4.1", "4.2"]
```

# Information security policy is documented, approved, and current

`NIST-CSF-2-GV.PO-01` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.PO-01 requires an organization-wide information
security policy to be established, communicated, and enforced.
Concord reads a cosigned policy attestation.

## Why it matters

GV.PO-01 is the meta-control auditors use to evaluate every other
PR/DE/RS control.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no policy attestation collected
- attestation kind is <value>, expected "information_security_policy"
- policy attestation missing field: <value>
- policy attestation cosign signature did not verify
- policy review is overdue

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1w**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.PO-01
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["GV.PO-01"]
  iso27001: ["A.5.1"]
```

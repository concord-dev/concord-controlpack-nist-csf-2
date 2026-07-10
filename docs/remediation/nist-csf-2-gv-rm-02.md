# Risk appetite and risk tolerance statements are established and communicated

`NIST-CSF-2-GV.RM-02` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.RM-02 requires that risk appetite and risk tolerance
statements are established, communicated, and maintained. Concord
reads a cosigned risk-appetite attestation that captures the risk
appetite statement, the quantified tolerance levels, and the
authority that approved them.

## Why it matters

Risk appetite and tolerance translate the risk-management strategy
into thresholds that make individual risk-acceptance decisions
consistent and auditable. Without an approved, quantified tolerance,
exception approvals and risk treatment are ad hoc and cannot be
defended to an auditor or the board.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no risk-appetite attestation collected
- attestation kind is <value>, expected "risk_appetite"
- risk-appetite attestation missing field: <value>
- no quantified risk tolerance levels defined
- risk-appetite attestation cosign signature did not verify
- risk appetite/tolerance not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.RM-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.RM-02"
  nist_800_53:
  - "PM-9"
  - "RA-3"
  iso27001:
  - "6.1.2"
  - "A.5.1"
  soc2:
  - "CC3.1"
```

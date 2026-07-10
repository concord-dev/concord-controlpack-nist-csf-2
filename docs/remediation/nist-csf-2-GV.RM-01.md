# Risk management objectives are established and agreed by stakeholders

`NIST-CSF-2-GV.RM-01` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.RM-01 requires the organization's risk-management
objectives to be established and agreed upon by stakeholders. Concord
verifies a signed risk-management-strategy attestation lists
objectives, the stakeholders who agreed to them, and a review cadence.

## Why it matters

GV.RM-01 is the upstream control feeding every other GV.RM finding in
a CSF 2.0 audit. Without an agreed strategy, auditors cannot tell
whether the org's risk register reflects an intentional posture.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no risk-management-strategy attestation collected
- attestation kind is <value>, expected "risk_management_strategy"
- strategy missing required field: <value>
- strategy lists zero objectives
- strategy has no stakeholders agreeing to the objectives

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.RM-01
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.RM-01"
  iso27001:
  - "A.5.1"
```

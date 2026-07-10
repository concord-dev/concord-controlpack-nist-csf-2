# Outcomes, capabilities, and services the organization depends on are understood

`NIST-CSF-2-GV.OC-05` · framework **nist-csf-2** · severity **medium** · Govern

## What this control checks

NIST CSF 2.0 GV.OC-05 requires that outcomes, capabilities, and
services that the organization depends on are understood and
communicated. Concord reads a cosigned cyber-dependencies
attestation listing the external capabilities and services the
organization relies on, together with the resilience requirements
placed on each.

## Why it matters

An organization's cybersecurity outcomes hinge on third-party and
infrastructure dependencies it does not directly control. Documenting
these dependencies and their resilience requirements is what lets
business-continuity and supply-chain risk decisions be grounded in
reality rather than assumption.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no cyber-dependencies attestation collected
- attestation kind is <value>, expected "cyber_dependencies"
- cyber-dependencies attestation missing field: <value>
- no depended-on capabilities or services identified
- no resilience requirements defined for depended-on services
- cyber-dependencies attestation cosign signature did not verify
- dependency inventory not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.OC-05
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.OC-05"
  nist_800_53:
  - "CP-2"
  - "PM-11"
  iso27001:
  - "A.5.30"
  soc2:
  - "A1.2"
```

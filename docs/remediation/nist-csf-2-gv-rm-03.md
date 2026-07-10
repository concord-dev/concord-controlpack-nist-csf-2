# Cybersecurity risk management is integrated into enterprise risk management

`NIST-CSF-2-GV.RM-03` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.RM-03 requires that cybersecurity risk management
activities and outcomes are included in enterprise risk management
(ERM) processes. Concord reads a cosigned erm-integration
attestation describing how cyber risk feeds the ERM process, how it
is reported, and the path by which material cyber risks are
escalated.

## Why it matters

Cyber risk treated in a silo is invisible to the executives and board
who own enterprise risk. GV.RM-03 is the control auditors use to
confirm cybersecurity risk is aggregated, reported, and escalated
alongside financial, operational, and strategic risk rather than
managed as a purely technical concern.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no erm-integration attestation collected
- attestation kind is <value>, expected "erm_integration"
- erm-integration attestation missing field: <value>
- erm-integration attestation cosign signature did not verify
- ERM integration not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.RM-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.RM-03"
  nist_800_53:
  - "PM-9"
  - "PM-28"
  iso27001:
  - "6.1.1"
  soc2:
  - "CC3.1"
  - "CC5.1"
```

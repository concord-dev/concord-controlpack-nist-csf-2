# Critical objectives, capabilities, and services are understood and communicated

`NIST-CSF-2-GV.OC-04` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.OC-04 requires that critical objectives,
capabilities, and services that external stakeholders depend on or
expect from the organization are understood and communicated.
Concord reads a cosigned critical-services attestation that
enumerates the critical services, their upstream dependencies, and
how criticality is communicated to those who must act on it.

## Why it matters

Recovery objectives, monitoring priorities, and supply-chain tiers
all derive from knowing which services are business-critical. If the
organization cannot name its critical services and their
dependencies, downstream Protect, Detect, and Recover controls are
prioritized blindly.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no critical-services attestation collected
- attestation kind is <value>, expected "critical_services"
- critical-services attestation missing field: <value>
- no critical services identified
- no service dependencies identified
- critical-services attestation cosign signature did not verify
- critical-services inventory not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.OC-04
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.OC-04"
  nist_800_53:
  - "PM-11"
  - "RA-9"
  - "CP-2"
  iso27001:
  - "A.5.30"
  soc2:
  - "A1.2"
```

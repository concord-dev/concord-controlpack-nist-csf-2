# Cybersecurity policy is reviewed, updated, communicated, and enforced

`NIST-CSF-2-GV.PO-02` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.PO-02 requires that the policy for managing
cybersecurity risks is reviewed, updated, communicated, and enforced
to reflect changes in requirements, threats, technology, and
organizational mission. Concord reads a cosigned
cyber-policy-management attestation recording the review cycle, how
policy changes are communicated, and the process for handling
exceptions.

## Why it matters

GV.PO-01 establishes that a policy exists; GV.PO-02 is the control
auditors use to confirm the policy is a living document rather than a
one-time artifact. A defined review cadence, communication path, and
exception process are what keep the policy aligned with a changing
threat and regulatory landscape.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no cyber-policy-management attestation collected
- attestation kind is <value>, expected "cyber_policy_management"
- cyber-policy-management attestation missing field: <value>
- cyber-policy-management attestation cosign signature did not verify
- cybersecurity policy not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.PO-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.PO-02"
  nist_800_53:
  - "PM-1"
  - "PL-1"
  iso27001:
  - "A.5.1"
  - "5.2"
  soc2:
  - "CC2.2"
```

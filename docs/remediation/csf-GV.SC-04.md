# Suppliers, including third-parties, are known and prioritized by criticality

`NIST-CSF-2-GV.SC-04` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.SC-04 requires suppliers to be known and prioritized
by criticality. Concord reads the Concord vendor-register attestation
and verifies every tier-1 supplier has a current certification.

## Why it matters

Supply-chain visibility is one of the most-cited GV findings.
Concord's vendor register makes the structured data available.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no vendor-register attestation collected
- vendor-register attestation signature did not verify
- vendor <value> has no tier assigned — every supplier must be prioritised by criticality
- tier-1 vendor <value> has no acceptable security certification

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.SC-04
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["GV.SC-04"]
  iso27001: ["A.5.19"]
  soc2: ["CC9.2"]
```

# Cybersecurity is included in human resources practices

`NIST-CSF-2-GV.RR-04` · framework **nist-csf-2** · severity **medium** · Govern

## What this control checks

NIST CSF 2.0 GV.RR-04 requires cybersecurity to be included in human
resources practices across the personnel lifecycle. Concord reads a
cosigned HR-security-integration attestation covering the pre-hire
screening process, the security steps performed at onboarding, the
offboarding process that removes access, and the date the integration
was last reviewed.

## Why it matters

Most insider and access-related findings trace back to gaps at hire
or departure. GV.RR-04 confirms that security is wired into HR rather
than bolted on. The attestation forces screening, onboarding, and
offboarding controls to be named and re-reviewed so departing staff
lose access promptly and new staff start with security obligations.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no HR-security-integration attestation collected
- attestation kind is <value>, expected <value>
- HR-security-integration attestation missing required field: <value>
- HR-security-integration attestation cosign signature did not verify
- HR security integration has not been reviewed in the last 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.RR-04
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.RR-04"
  nist_800_53:
  - "PS-2"
  - "PS-3"
  - "PS-4"
  - "PS-5"
  iso27001:
  - "A.6.1"
  - "A.6.2"
  - "A.6.5"
  soc2:
  - "CC1.4"
```

# Integrity of restored assets is verified before returning them to operations

`NIST-CSF-2-RC.RP-05` · framework **nist-csf-2** · severity **high** · Recover

## What this control checks

NIST CSF 2.0 RC.RP-05 requires that the integrity of restored assets be
verified before they are returned to normal operations, and that operational
status be confirmed. Concord reads a cosigned restoration-verification
attestation that records the procedure used to verify a restored asset, the
acceptance criteria it must meet, the role authorized to sign off on the
return to operations, and when the procedure was last reviewed.

## Why it matters

Returning a restored asset to production without verifying it risks
reintroducing the very malware, misconfiguration, or corruption that caused
the incident, turning one outage into a reinfection loop. A defined
verification procedure with explicit acceptance criteria and a named sign-off
role forces a deliberate go/no-go decision. The signed attestation proves
that gate exists, is owned, and is kept current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no restoration-verification attestation collected
- attestation kind is <value>, expected "restoration_verification"
- restoration-verification attestation cosign signature did not verify
- restoration-verification attestation missing field: <value>
- restoration verification procedure last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RC.RP-05
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RC.RP-05"]
  nist_800_53: ["CP-10", "CP-4", "SI-7"]
  iso27001: ["A.5.30", "A.8.13"]
  soc2: ["A1.3", "CC7.5"]
```

# Hardware is managed throughout its lifecycle

`NIST-CSF-2-PR.PS-03` · framework **nist-csf-2** · severity **medium** · Protect

## What this control checks

NIST CSF 2.0 PR.PS-03 requires that hardware is managed throughout its
lifecycle — maintained, replaced, and removed — commensurate with risk.
Concord reads a signed attestation for the hardware lifecycle program and
verifies that it documents the maintenance process, the criteria used to
replace aging or unsupported hardware, that retired hardware is securely
sanitized or destroyed before disposal, and a recent review date.

## Why it matters

Unmaintained or end-of-life hardware accumulates unpatched firmware and
failure risk, and improperly disposed media is a common source of data
leakage. Documented maintenance, replacement, and media-sanitization
practices are the baseline for managing hardware risk over its lifecycle.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no hardware-lifecycle attestation collected
- attestation kind is <value>, expected "hardware_lifecycle"
- hardware-lifecycle attestation signature did not verify
- attestation does not document a hardware maintenance process
- attestation does not document hardware replacement criteria
- attestation does not confirm secure sanitization/disposal of retired hardware
- attestation records no last_reviewed_at date

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.PS-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["PR.PS-03"]
  nist_800_53: ["MA-2", "MP-6"]
  iso27001: ["A.7.14"]
  soc2: ["CC6.5"]
```

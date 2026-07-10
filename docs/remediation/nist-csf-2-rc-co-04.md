# Public updates on incident recovery are shared using approved methods and messaging

`NIST-CSF-2-RC.CO-04` · framework **nist-csf-2** · severity **low** · Recover

## What this control checks

NIST CSF 2.0 RC.CO-04 requires that public updates on incident recovery be
shared using approved methods and messaging. Concord reads a cosigned
public-recovery-updates attestation that records the documented process for
issuing public statements, the authority that must approve external
messaging, the sanctioned communication channels, and when the process was
last reviewed.

## Why it matters

Public statements made during a recovery are legally and reputationally
consequential, so they cannot be posted by whoever happens to hold the
keyboard. Requiring a defined approval authority and approved channels
prevents premature, inconsistent, or unvetted disclosures. The signed
attestation proves the public-communication process exists, is owned, and is
kept current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no public-recovery-updates attestation collected
- attestation kind is <value>, expected "public_recovery_updates"
- public-recovery-updates attestation cosign signature did not verify
- public-recovery-updates attestation missing field: <value>
- public-recovery-updates process last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RC.CO-04
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RC.CO-04"]
  nist_800_53: ["IR-4", "CP-2"]
  iso27001: ["A.5.24"]
  soc2: ["CC2.3"]
```

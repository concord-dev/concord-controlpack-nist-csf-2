# Internal and external threats are identified and recorded

`NIST-CSF-2-ID.RA-03` · framework **nist-csf-2** · severity **high** · Identify

## What this control checks

NIST CSF 2.0 ID.RA-03 requires internal and external threats to the
organization to be identified and recorded. Concord verifies a signed
threat-identification attestation that enumerates both the internal and
external threats considered, states the method used to record them, and
shows the threat set was reviewed within the last year.

## Why it matters

Risk cannot be determined (ID.RA-05) without an explicit threat model
covering both insider and adversary scenarios. ID.RA-03 fails when
either the internal or external threat list is empty or the threats are
not recorded anywhere durable, because unrecorded threats are silently
dropped from every subsequent risk calculation.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no threat-identification attestation collected
- attestation kind is <value>, expected "threat_identification"
- threat identification missing required field: <value>
- threat-identification attestation cosign signature did not verify
- threat identification records zero internal threats
- threat identification records zero external threats
- threat identification has not been reviewed in over <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.RA-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "ID.RA-03"
  nist_800_53:
  - "RA-3"
  - "PM-16"
  iso27001:
  - "A.5.7"
```

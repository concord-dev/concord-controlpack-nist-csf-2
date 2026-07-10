# Improvements to organizational cybersecurity are identified

`NIST-CSF-2-ID.IM-01` · framework **nist-csf-2** · severity **medium** · Identify

## What this control checks

NIST CSF 2.0 ID.IM-01 requires improvements to be identified from
evaluations such as tests, exercises, audits, and lessons learned.
Concord verifies a signed improvement-process attestation that
enumerates the sources feeding the improvement pipeline, states the
cadence at which they are reviewed, names the mechanism used to track
improvements to closure, and shows the process was reviewed within the
last year.

## Why it matters

A framework program only stays effective if findings from evaluations
are captured and driven to closure. ID.IM-01 fails when there are no
identified improvement sources or no tracking mechanism, meaning
lessons from incidents, audits, and exercises evaporate and the same
weaknesses recur.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no improvement-process attestation collected
- attestation kind is <value>, expected "improvement_process"
- improvement process missing required field: <value>
- improvement-process attestation cosign signature did not verify
- improvement process identifies zero improvement sources
- improvement process has not been reviewed in over <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.IM-01
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "ID.IM-01"
  nist_800_53:
  - "CA-7"
  - "PM-4"
  soc2:
  - "CC4.2"
```

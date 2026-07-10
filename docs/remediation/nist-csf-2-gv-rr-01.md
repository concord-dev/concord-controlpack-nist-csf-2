# Organizational leadership is responsible and accountable for cybersecurity risk

`NIST-CSF-2-GV.RR-01` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.RR-01 requires organizational leadership to be
responsible and accountable for cybersecurity risk and to foster a
culture that is risk-aware, ethical, and continually improving.
Concord reads a cosigned leadership-accountability attestation that
names the accountable executive, the board-level oversight body, the
cadence on which cyber risk is reported to that body, and the date
leadership last reviewed the organization's cybersecurity risk posture.

## Why it matters

Auditors treat GV.RR-01 as the test of whether cyber risk has a named,
senior owner rather than being diffused across the organization. The
attestation forces a specific accountable executive and an active board
oversight cadence to be recorded, cosigned, and re-reviewed, so the
accountability cannot silently lapse.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no leadership-accountability attestation collected
- attestation kind is <value>, expected <value>
- leadership-accountability attestation missing required field: <value>
- leadership-accountability attestation cosign signature did not verify
- leadership review of cybersecurity risk is older than 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1w**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.RR-01
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.RR-01"
  nist_800_53:
  - "PM-2"
  - "PM-29"
  iso27001:
  - "A.5.2"
  - "A.5.4"
  soc2:
  - "CC1.2"
```

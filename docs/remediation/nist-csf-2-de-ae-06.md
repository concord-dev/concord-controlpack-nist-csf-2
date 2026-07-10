# Information on adverse events is provided to authorized staff and tools

`NIST-CSF-2-DE.AE-06` · framework **nist-csf-2** · severity **medium** · Detect

## What this control checks

NIST CSF 2.0 DE.AE-06 requires that information on adverse events is
provided to authorized staff and tools. Concord reads a cosigned
event-notification attestation that records the notification process, the
authorized recipients who receive event information, the channels used to
deliver it, and the date the process was last reviewed.

## Why it matters

Analysis that never reaches a responder is wasted work. This control checks
that detected events are routed — promptly and to explicitly authorized
recipients over defined channels — so that the people and downstream tools
positioned to act actually receive them. A missing or stale routing process
is how events sit unactioned in a queue nobody watches, so Concord fails
closed when the attestation is absent, unsigned, incomplete, or overdue for
review.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no event-notification attestation collected
- attestation kind is <value>, expected "event_notification"
- event-notification attestation missing field: <value>
- event-notification attestation cosign signature did not verify
- event-notification process not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-DE.AE-06
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "DE.AE-06"
  nist_800_53:
  - "AU-6"
  - "IR-4"
  - "IR-6"
  iso27001:
  - "A.6.8"
  soc2:
  - "CC2.2"
  - "CC7.3"
```

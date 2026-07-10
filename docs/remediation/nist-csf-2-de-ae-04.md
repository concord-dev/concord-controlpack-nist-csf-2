# The estimated impact and scope of adverse events are understood

`NIST-CSF-2-DE.AE-04` · framework **nist-csf-2** · severity **high** · Detect

## What this control checks

NIST CSF 2.0 DE.AE-04 requires that the estimated impact and scope of
adverse events are understood. Concord reads a cosigned
event-impact-analysis attestation that records the impact criteria applied,
the method used to scope affected assets and data, the escalation
thresholds that route an event by severity, and the date the process was
last reviewed.

## Why it matters

Response decisions — who to notify, whether to declare an incident, how
much to spend containing it — all hang on a defensible estimate of impact
and blast radius. When impact and scope are judged ad hoc, similar events
receive wildly different handling and severe events are under-reacted to.
Pre-agreed impact criteria and scoping methods make those judgements
repeatable and reviewable, so Concord fails closed when the attestation is
missing, unsigned, incomplete, or stale.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no event-impact-analysis attestation collected
- attestation kind is <value>, expected "event_impact_analysis"
- event-impact-analysis attestation missing field: <value>
- event-impact-analysis attestation cosign signature did not verify
- impact/scope analysis criteria not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-DE.AE-04
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "DE.AE-04"
  nist_800_53:
  - "IR-4"
  - "AU-6"
  - "RA-3"
  iso27001:
  - "A.5.25"
  soc2:
  - "CC7.3"
```

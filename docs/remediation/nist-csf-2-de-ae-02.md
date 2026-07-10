# Potentially adverse events are analyzed to understand associated activities

`NIST-CSF-2-DE.AE-02` · framework **nist-csf-2** · severity **high** · Detect

## What this control checks

NIST CSF 2.0 DE.AE-02 requires that potentially adverse events are
analyzed to better understand the associated activities. Concord reads a
cosigned event-analysis-process attestation that records the documented
analysis procedures analysts follow, the tooling used to triage and
correlate events, the analyst roles responsible, and the date the process
was last reviewed.

## Why it matters

Detection tooling generates far more signals than can be acted on blindly;
the control is satisfied only when there is a defined, staffed process for
turning raw alerts into an understanding of what actually happened. An
absent, unsigned, or stale analysis process is the tell-tale of alerts that
are collected but never investigated, which is exactly the failure mode
auditors probe for. Concord fails closed when the attestation is missing,
the wrong kind, unsigned, incomplete, or older than the review window.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no event-analysis-process attestation collected
- attestation kind is <value>, expected "event_analysis_process"
- event-analysis-process attestation missing field: <value>
- event-analysis-process attestation cosign signature did not verify
- event-analysis process not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-DE.AE-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "DE.AE-02"
  nist_800_53:
  - "AU-6"
  - "IR-4"
  - "SI-4"
  iso27001:
  - "A.5.25"
  soc2:
  - "CC7.2"
  - "CC7.3"
```

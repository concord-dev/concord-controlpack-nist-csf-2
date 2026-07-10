# The physical environment is monitored to find potentially adverse events

`NIST-CSF-2-DE.CM-02` · framework **nist-csf-2** · severity **medium** · Detect

## What this control checks

NIST CSF 2.0 DE.CM-02 requires that the physical environment is monitored
to find potentially adverse events. Concord reads a cosigned
physical-monitoring attestation that records the monitoring controls in
place (such as CCTV, badge and access logging, and environmental sensors),
the coverage areas those controls span, the alerting that turns a physical
anomaly into a response, and the date the arrangement was last reviewed.

## Why it matters

Physical monitoring is largely off-cloud — cameras, badge readers, and
facility sensors managed by a landlord or facilities team — so a signed,
current attestation is the practical evidence that coverage exists and is
wired to alerting. Cameras that record but alert no one, or coverage that
silently lapses after an office move, defeat the control. Concord fails
closed when the attestation is missing, unsigned, incomplete, or older than
the review window.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no physical-monitoring attestation collected
- attestation kind is <value>, expected "physical_monitoring"
- physical-monitoring attestation missing field: <value>
- physical-monitoring attestation cosign signature did not verify
- physical-monitoring arrangement not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-DE.CM-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "DE.CM-02"
  nist_800_53:
  - "PE-6"
  - "PE-3"
  - "CA-7"
  iso27001:
  - "A.7.4"
  soc2:
  - "CC6.4"
```

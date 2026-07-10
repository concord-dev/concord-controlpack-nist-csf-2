# Cyber threat intelligence and contextual information are integrated into analysis

`NIST-CSF-2-DE.AE-07` · framework **nist-csf-2** · severity **medium** · Detect

## What this control checks

NIST CSF 2.0 DE.AE-07 requires that cyber threat intelligence and other
contextual information are integrated into the analysis of adverse events.
Concord reads a cosigned cti-integration attestation that records the intel
feeds consumed, the process used to tune detection content from that
intelligence, the cadence on which the integration is reviewed, and the
date the process was last reviewed.

## Why it matters

Threat intelligence improves detection only when it is operationalised —
translated into detection rules, watchlists, and enrichment — and kept
current as adversary tradecraft shifts. A feed that is subscribed to but
never wired into tuning adds cost without coverage, and stale intelligence
quietly decays into noise. Concord fails closed when the attestation is
missing, unsigned, incomplete, or older than the review window, so that
"we have a threat-intel feed" cannot stand in for actually using it.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no cti-integration attestation collected
- attestation kind is <value>, expected "cti_integration"
- cti-integration attestation missing field: <value>
- cti-integration attestation cosign signature did not verify
- threat-intelligence integration not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-DE.AE-07
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "DE.AE-07"
  nist_800_53:
  - "SI-4"
  - "PM-16"
  - "RA-3"
  iso27001:
  - "A.5.7"
  soc2:
  - "CC7.2"
```

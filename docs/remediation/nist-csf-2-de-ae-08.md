# Incidents are declared when adverse events meet defined incident criteria

`NIST-CSF-2-DE.AE-08` · framework **nist-csf-2** · severity **high** · Detect

## What this control checks

NIST CSF 2.0 DE.AE-08 requires that incidents are declared when adverse
events meet the organization's defined incident criteria. Concord reads a
cosigned incident-declaration attestation that records the declaration
criteria, the severity matrix used to classify a declared incident, the
decision authority empowered to declare, and the date the process was last
reviewed.

## Why it matters

Declaring an incident is what activates the response plan, notification
clocks, and regulatory timelines; if the trigger is left to individual
judgement, genuine incidents get quietly closed as "just an alert" and
response is delayed. Objective, pre-agreed criteria, a severity matrix, and
a named decision authority make declaration consistent and defensible.
Concord fails closed when the attestation is missing, unsigned, incomplete,
or stale, because an undocumented declaration bar is effectively no bar.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-declaration attestation collected
- attestation kind is <value>, expected "incident_declaration"
- incident-declaration attestation missing field: <value>
- incident-declaration attestation cosign signature did not verify
- incident-declaration criteria not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-DE.AE-08
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "DE.AE-08"
  nist_800_53:
  - "IR-4"
  - "IR-8"
  - "AU-6"
  iso27001:
  - "A.5.25"
  soc2:
  - "CC7.3"
  - "CC7.4"
```

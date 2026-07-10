# Incident reports are triaged and validated

`NIST-CSF-2-RS.MA-02` · framework **nist-csf-2** · severity **high** · Respond

## What this control checks

NIST CSF 2.0 RS.MA-02 requires that incident reports be triaged and
validated so that genuine incidents are distinguished from false
positives and handled within defined service levels. Concord reads a
cosigned incident-triage attestation that records the documented
triage process, the criteria used to validate that a report is a real
incident, the triage SLA targets, and when the process was last
reviewed.

## Why it matters

Without a validated triage step, responders burn effort on false
positives while real incidents slip past their SLA. The signed
attestation proves the triage and validation process exists, is
owned, and is kept current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-triage attestation collected
- attestation kind is <value>, expected "incident_triage"
- incident-triage attestation cosign signature did not verify
- incident-triage attestation missing field: <value>
- triage process last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.MA-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.MA-02"]
  nist_800_53: ["IR-4", "IR-5", "IR-8"]
  iso27001: ["A.5.25", "A.5.26"]
  soc2: ["CC7.3", "CC7.4"]
```

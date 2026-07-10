# Incidents are escalated or elevated as needed

`NIST-CSF-2-RS.MA-04` · framework **nist-csf-2** · severity **high** · Respond

## What this control checks

NIST CSF 2.0 RS.MA-04 requires that incidents be escalated or elevated
when their severity, scope, or duration crosses defined thresholds.
Concord reads a cosigned incident-escalation attestation that records
the escalation criteria/thresholds, the escalation paths and contacts,
the authority empowered to make escalation decisions, and when the
escalation process was last reviewed.

## Why it matters

Clear escalation criteria and paths keep a contained incident from
quietly becoming a crisis because no one had the authority or contact
list to raise it. The signed attestation proves the escalation process
exists, is owned, and is kept current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-escalation attestation collected
- attestation kind is <value>, expected "incident_escalation"
- incident-escalation attestation cosign signature did not verify
- incident-escalation attestation missing field: <value>
- escalation process last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.MA-04
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.MA-04"]
  nist_800_53: ["IR-4", "IR-5", "IR-8"]
  iso27001: ["A.5.24", "A.5.26"]
  soc2: ["CC7.4"]
```

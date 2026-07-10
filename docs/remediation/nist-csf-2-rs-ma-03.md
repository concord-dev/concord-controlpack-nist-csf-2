# Incidents are categorized and prioritized

`NIST-CSF-2-RS.MA-03` · framework **nist-csf-2** · severity **high** · Respond

## What this control checks

NIST CSF 2.0 RS.MA-03 requires that incidents be categorized and
prioritized so that response effort is directed at the incidents that
matter most. Concord reads a cosigned incident-categorization
attestation that records the category scheme, the priority/severity
matrix, the rules for assigning an incident to a responder or team,
and when the scheme was last reviewed.

## Why it matters

A shared category scheme and priority matrix keep responders from
guessing at severity and ownership under pressure. The signed
attestation proves the scheme exists, is owned, and is kept current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-categorization attestation collected
- attestation kind is <value>, expected "incident_categorization"
- incident-categorization attestation cosign signature did not verify
- incident-categorization attestation missing field: <value>
- categorization scheme last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.MA-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.MA-03"]
  nist_800_53: ["IR-4", "IR-5", "IR-8"]
  iso27001: ["A.5.25"]
  soc2: ["CC7.3", "CC7.4"]
```

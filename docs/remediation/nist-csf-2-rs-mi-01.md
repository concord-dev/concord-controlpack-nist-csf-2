# Incidents are contained

`NIST-CSF-2-RS.MI-01` · framework **nist-csf-2** · severity **critical** · Respond

## What this control checks

NIST CSF 2.0 RS.MI-01 requires that incidents be contained to limit
their spread and impact. Concord reads a cosigned incident-containment
attestation that records the containment playbooks in use, the
isolation procedures for endpoints/accounts/network segments, the
authority empowered to order containment, and when the playbooks were
last reviewed.

## Why it matters

Fast, pre-authorized containment is what stops an intrusion from
becoming a breach. Documented playbooks and clear isolation authority
remove the hesitation that lets an incident spread. The signed
attestation proves the containment capability exists, is owned, and is
kept current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-containment attestation collected
- attestation kind is <value>, expected "incident_containment"
- incident-containment attestation cosign signature did not verify
- incident-containment attestation missing field: <value>
- containment playbooks last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.MI-01
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.MI-01"]
  nist_800_53: ["IR-4"]
  iso27001: ["A.5.26"]
  soc2: ["CC7.4"]
```

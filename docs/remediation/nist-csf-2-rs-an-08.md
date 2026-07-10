# The magnitude of an incident is estimated and validated

`NIST-CSF-2-RS.AN-08` · framework **nist-csf-2** · severity **medium** · Respond

## What this control checks

NIST CSF 2.0 RS.AN-08 requires that an incident's magnitude is
estimated and validated. Concord reads a cosigned attestation that
records the estimation method used to size an incident, the validation
process that confirms or corrects the estimate, and the impact
categories (for example financial, operational, safety, reputational,
and regulatory) the organization scores.

## Why it matters

Response prioritization, escalation, and stakeholder notification all
depend on a credible estimate of an incident's magnitude. Attesting to
a documented estimation method, a validation step that guards against
over- or under-estimation, and the impact categories scored — reviewed
at least annually — demonstrates that magnitude is derived
systematically rather than ad hoc.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-magnitude attestation collected
- attestation kind is <value>, expected <value>
- incident-magnitude attestation cosign signature did not verify
- incident-magnitude attestation missing required field: <value>
- incident-magnitude attestation scores zero impact categories
- incident-magnitude method last reviewed <value> — older than <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1w**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.AN-08
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.AN-08"]
  nist_800_53: ["IR-4", "AU-6", "IR-5"]
  iso27001: ["A.5.25"]
  soc2: ["CC7.4"]
```

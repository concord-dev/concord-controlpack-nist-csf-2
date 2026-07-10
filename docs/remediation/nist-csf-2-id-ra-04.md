# Potential impacts and likelihoods of threats are recorded

`NIST-CSF-2-ID.RA-04` · framework **nist-csf-2** · severity **high** · Identify

## What this control checks

NIST CSF 2.0 ID.RA-04 requires the potential impacts and likelihoods of
threats exploiting vulnerabilities to be identified and recorded.
Concord verifies a signed risk-impact attestation that publishes the
impact scale and likelihood scale in use, records a set of risks scored
against those scales, and shows the analysis was reviewed within the
last year.

## Why it matters

Risk cannot be prioritized without consistent impact and likelihood
scales applied to recorded risks. ID.RA-04 fails when the scales are
undefined or no risks have been scored, because impact and likelihood
then become ad hoc judgements that cannot be compared, ranked, or
tracked over time.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no risk-impact-analysis attestation collected
- attestation kind is <value>, expected "risk_impact_analysis"
- risk impact analysis missing required field: <value>
- risk-impact-analysis attestation cosign signature did not verify
- risk impact analysis defines no impact scale
- risk impact analysis defines no likelihood scale
- risk impact analysis has scored zero risks
- risk impact analysis has not been reviewed in over <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.RA-04
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "ID.RA-04"
  nist_800_53:
  - "RA-3"
  - "PM-16"
  soc2:
  - "CC3.2"
```

# Threats, vulnerabilities, likelihoods, and impacts are used to determine risk

`NIST-CSF-2-ID.RA-05` · framework **nist-csf-2** · severity **high** · Identify

## What this control checks

NIST CSF 2.0 ID.RA-05 requires threats, vulnerabilities, likelihoods,
and impacts to be used to understand inherent risk and to inform risk
prioritization. Concord verifies a signed risk-determination attestation
that documents the methodology combining those inputs, publishes the
resulting prioritized set of risks, states the cadence at which risk is
re-determined, and shows the analysis was reviewed within the last year.

## Why it matters

ID.RA-05 is the synthesis step that turns the threat model (ID.RA-03)
and the impact/likelihood analysis (ID.RA-04) into a prioritized risk
picture the business acts on. It fails when there is no documented
methodology or no prioritized risks, because risk treatment decisions
then have no defensible, repeatable basis.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no risk-determination attestation collected
- attestation kind is <value>, expected "risk_determination"
- risk determination missing required field: <value>
- risk-determination attestation cosign signature did not verify
- risk determination produced zero prioritized risks
- risk determination has not been reviewed in over <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.RA-05
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "ID.RA-05"
  nist_800_53:
  - "RA-3"
  - "RA-5"
  - "PM-16"
  soc2:
  - "CC3.2"
```

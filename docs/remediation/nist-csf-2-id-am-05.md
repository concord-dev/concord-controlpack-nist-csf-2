# Assets are prioritized based on classification, criticality, and value

`NIST-CSF-2-ID.AM-05` · framework **nist-csf-2** · severity **medium** · Identify

## What this control checks

NIST CSF 2.0 ID.AM-05 requires assets to be prioritized based on their
classification, criticality, resources, and impact on the mission.
Concord verifies a signed asset-prioritization attestation that records
the classification scheme in use, the criteria used to judge
criticality, the resulting prioritized set of assets, and evidence the
prioritization was reviewed within the last year.

## Why it matters

Finite security resources must be concentrated on the assets that
matter most. ID.AM-05 fails when there is no classification scheme or
no prioritized asset list, because without prioritization every
downstream control (monitoring depth, recovery objectives, access
restriction) is applied uniformly and the highest-value systems are
under-protected.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no asset-prioritization attestation collected
- attestation kind is <value>, expected "asset_prioritization"
- asset prioritization missing required field: <value>
- asset-prioritization attestation cosign signature did not verify
- asset prioritization defines zero criticality criteria
- asset prioritization ranks zero assets
- asset prioritization has not been reviewed in over <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.AM-05
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "ID.AM-05"
  nist_800_53:
  - "CM-8"
  - "PM-5"
  iso27001:
  - "A.5.9"
  - "A.5.12"
```

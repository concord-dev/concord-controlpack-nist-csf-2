# Systems, hardware, software, and services are managed throughout their lifecycle

`NIST-CSF-2-ID.AM-08` · framework **nist-csf-2** · severity **medium** · Identify

## What this control checks

NIST CSF 2.0 ID.AM-08 requires systems, hardware, software, services,
and data to be managed throughout their life cycles. Concord verifies a
signed asset-lifecycle attestation that defines the lifecycle stages an
asset moves through, documents the decommissioning process, describes
how ownership is tracked across those stages, and shows the process was
reviewed within the last year.

## Why it matters

Most exposure accrues at the edges of the lifecycle: assets provisioned
without ownership and assets retired without secure disposal. ID.AM-08
fails when there are no defined lifecycle stages or no decommissioning
process, leaving orphaned and unwiped assets that keep credentials and
data reachable long after they should have been retired.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no asset-lifecycle attestation collected
- attestation kind is <value>, expected "asset_lifecycle"
- asset lifecycle attestation missing required field: <value>
- asset-lifecycle attestation cosign signature did not verify
- asset lifecycle defines zero lifecycle stages
- asset lifecycle process has not been reviewed in over <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.AM-08
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "ID.AM-08"
  nist_800_53:
  - "CM-8"
  - "PM-5"
  iso27001:
  - "A.5.9"
  - "A.8.10"
```

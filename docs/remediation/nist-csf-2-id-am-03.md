# Organizational hardware is inventoried and maintained

`NIST-CSF-2-ID.AM-03` · framework **nist-csf-2** · severity **high** · Identify

## What this control checks

NIST CSF 2.0 ID.AM-03 requires the organization to maintain an
inventory of the hardware it manages. For a cloud-first estate the
"hardware" is the compute the organization runs (for example EC2/EKS
workloads), so Concord verifies the AWS Config recorder is active — it
is the authoritative resource inventory — and that every instance
carries the ownership tags (owner, environment, data_classification)
that make it a tracked, accountable asset.

## Why it matters

An asset that is not recorded cannot be patched, monitored, or
decommissioned, and it is invisible to every downstream Identify and
Protect control. ID.AM-03 audits fail when Config is disabled or when
untagged, orphaned instances exist that no owner is accountable for.

## Evidence

Collected from the `aws` source (`ec2_inventory` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no hardware/cloud asset inventory evidence collected
- AWS Config recorder is not active — authoritative asset inventory is missing
- asset <value> is missing required inventory tag <value>

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.AM-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "ID.AM-03"
  nist_800_53:
  - "CM-8"
  - "PM-5"
  iso27001:
  - "A.5.9"
```

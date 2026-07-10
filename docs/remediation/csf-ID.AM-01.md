# Inventories of authorised hardware/cloud assets are maintained

`NIST-CSF-2-ID.AM-01` · framework **nist-csf-2** · severity **high** · Identify

## What this control checks

NIST CSF 2.0 ID.AM-01 requires inventories of hardware managed by
the organization to be maintained. For cloud-first organizations,
Concord verifies AWS Config recorder is enabled (provides the
authoritative resource inventory) and that every EC2 instance is
tagged with required ownership fields.

## Why it matters

Cloud-native version of ID.AM-01 — the "hardware" is EC2/EKS
workloads, and Config recorder is the inventory.

## Evidence

Collected from the `aws` source (`ec2_inventory` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no EC2 inventory evidence collected
- AWS Config recorder is not active — authoritative inventory missing
- EC2 instance <value> is missing required tag <value>

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.AM-01
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["ID.AM-01"]
  iso27001: ["A.5.9", "A.5.23"]
```

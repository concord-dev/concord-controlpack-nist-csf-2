# Inventories of data and metadata are maintained

`NIST-CSF-2-ID.AM-07` · framework **nist-csf-2** · severity **high** · Identify

## What this control checks

NIST CSF 2.0 ID.AM-07 requires inventories of data and corresponding
metadata for designated data types to be maintained. Concord verifies a
signed data-inventory attestation that enumerates the data categories
the organization holds, names an owner for each, records the
classification scheme applied, and shows the inventory was reviewed
within the last year.

## Why it matters

Data protection controls (PR.DS) cannot be scoped to data that is not
inventoried. ID.AM-07 fails when data categories are undocumented or
unowned, because unclassified data receives no defined handling,
encryption, or retention requirement and is the most common source of
breach exposure.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no data-inventory attestation collected
- attestation kind is <value>, expected "data_inventory"
- data inventory missing required field: <value>
- data-inventory attestation cosign signature did not verify
- data inventory lists zero data categories
- data inventory assigns no owners to its data categories
- data inventory has not been reviewed in over <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.AM-07
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "ID.AM-07"
  nist_800_53:
  - "CM-8"
  - "PM-5"
  iso27001:
  - "A.5.9"
  - "A.5.12"
  - "A.5.13"
```

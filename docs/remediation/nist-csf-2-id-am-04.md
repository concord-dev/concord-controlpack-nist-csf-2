# Inventories of services provided by suppliers are maintained

`NIST-CSF-2-ID.AM-04` · framework **nist-csf-2** · severity **high** · Identify

## What this control checks

NIST CSF 2.0 ID.AM-04 requires the organization to maintain an
inventory of the services it obtains from suppliers. Concord verifies
a signed supplier-services attestation that enumerates each externally
provided service, maps every service to the supplier that delivers it,
records how supplier criticality is rated, and shows the inventory was
reviewed within the last year.

## Why it matters

Supplier services are part of the attack surface even though the
organization does not run them. ID.AM-04 fails when third-party
dependencies are undocumented, because an unmapped supplier cannot be
risk-tiered, monitored (DE.CM-06), or included in incident response,
leaving supply-chain exposure invisible to the risk program.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no supplier-services-inventory attestation collected
- attestation kind is <value>, expected "supplier_services_inventory"
- supplier-services inventory missing required field: <value>
- supplier-services-inventory attestation cosign signature did not verify
- supplier-services inventory lists zero services
- supplier-services inventory maps no services to their suppliers
- supplier-services inventory has not been reviewed in over <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.AM-04
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "ID.AM-04"
  nist_800_53:
  - "CM-8"
  - "PM-5"
  iso27001:
  - "A.5.19"
  - "A.5.21"
```

# Legal, regulatory, and contractual cybersecurity requirements are understood

`NIST-CSF-2-GV.OC-03` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.OC-03 requires that legal, regulatory, and
contractual requirements regarding cybersecurity — including privacy
and civil liberties obligations — are understood and managed.
Concord reads a cosigned legal-regulatory-requirements attestation
listing the applicable regulations, the contractual obligations, and
the process used to track them as they change.

## Why it matters

Unmanaged compliance obligations are one of the highest-impact
governance gaps: a missed statutory or contractual requirement can
convert a routine incident into regulatory enforcement or breach of
contract. A signed, current register lets auditors confirm the
organization knows which obligations bind it and how it stays
current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no legal-regulatory-requirements attestation collected
- attestation kind is <value>, expected "legal_regulatory_requirements"
- legal-regulatory attestation missing field: <value>
- no applicable regulations enumerated
- no contractual obligations enumerated
- legal-regulatory attestation cosign signature did not verify
- legal/regulatory register not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.OC-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.OC-03"
  nist_800_53:
  - "PM-11"
  - "PL-2"
  iso27001:
  - "A.5.31"
  - "A.5.34"
  soc2:
  - "CC2.3"
```

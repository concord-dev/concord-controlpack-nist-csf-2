# Physical access to assets is managed, monitored, and enforced

`NIST-CSF-2-PR.AA-06` · framework **nist-csf-2** · severity **medium** · Protect

## What this control checks

NIST CSF 2.0 PR.AA-06 requires that physical access to assets is managed,
monitored, and enforced commensurate with risk. Concord reads a signed
attestation for the facilities that hold in-scope assets (offices, data
centers, or a colocation/cloud provider's audited facilities) and verifies
that it documents the physical access-control measures in place, the roles
authorized to enter, that entry is logged, and a recent review date.

## Why it matters

Logical controls can be bypassed by anyone with physical access to
hardware, media, or network ports. Managed entry (badging, escorts,
mantraps), a bounded set of authorized roles, and access logging are the
baseline physical safeguards; for cloud-hosted assets this is typically
satisfied by the provider's attested facility controls.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no physical-access attestation collected
- attestation kind is <value>, expected "physical_access"
- physical-access attestation signature did not verify
- attestation names no physical access-control measures (e.g. badge readers, mantrap, biometrics)
- attestation does not enumerate the roles authorized for physical entry
- attestation does not confirm that physical access is logged
- attestation records no last_reviewed_at date

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.AA-06
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["PR.AA-06"]
  nist_800_53: ["AC-3", "PE-3"]
  iso27001: ["A.7.2"]
  soc2: ["CC6.4"]
```

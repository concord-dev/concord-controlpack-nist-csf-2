# Configuration management practices are established

`NIST-CSF-2-PR.PS-01` · framework **nist-csf-2** · severity **high** · Protect

## What this control checks

NIST CSF 2.0 subcategory PR.PS-01 (Platform Security) requires that
configuration management practices be established and applied so that the
current configuration of every system component is authoritatively
maintained. The AWS-side technical minimum is that the AWS Config recorder
is enabled and recording in every active region, so the configuration of
all resources is continuously and tamper-evidently captured. Concord reads
the Config recorder status and denies any active region where the recorder
is absent or not recording, and denies when no active regions are reported
at all. This implements NIST 800-53 CM-2 (Baseline Configuration) as the
control behind PR.PS-01. An absent evidence payload denies (fail-closed).

## Why it matters

Configuration management provides no assurance unless the current state of
every resource is continuously captured and comparable to an approved
baseline. The AWS Config recorder produces exactly that authoritative,
time-stamped record; if it is disabled in a region, configuration drift and
unauthorized changes there are invisible and no baseline can be maintained
for those resources. Requiring recording in every active region prevents the
false assurance of coverage that only spans part of the estate, and the
fail-closed default denies on missing evidence or a non-recording region
rather than assuming that region is adequately covered.

## Evidence

Collected from the `aws` source (`config_recorder_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- NIST CSF 2.0 PR.PS-01: no AWS Config recorder evidence collected — cannot demonstrate established configuration management (NIST 800-53 CM-2)
- NIST CSF 2.0 PR.PS-01: no active regions reported — cannot demonstrate configuration recording coverage (NIST 800-53 CM-2)
- NIST CSF 2.0 PR.PS-01: AWS Config recorder is not recording in active region <value> — configuration is not captured there (NIST 800-53 CM-2)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.PS-01
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "PR.PS-01"
  nist_800_53:
  - "CM-2"
  - "CM-8"
  soc2:
  - "CC7.1"
  pci_dss:
  - "2.2.1"
```

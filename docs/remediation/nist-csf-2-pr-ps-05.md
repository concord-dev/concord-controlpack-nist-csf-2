# Installation and execution of unauthorized software is prevented

`NIST-CSF-2-PR.PS-05` · framework **nist-csf-2** · severity **high** · Protect

## What this control checks

NIST CSF 2.0 PR.PS-05 requires that the installation and execution of
unauthorized software is prevented. Concord reads a signed attestation for
the software allowlisting program and verifies that it documents the
allowlisting method/technology (e.g. WDAC, AppLocker, MDM app control,
signed-image policy), the enforcement points it covers, the exception
process for authorizing new software, and a recent review date.

## Why it matters

Allowlisting is one of the most effective controls against malware and
living-off-the-land attacks because it blocks unknown binaries by default.
An attested method, broad enforcement coverage, and a governed exception
path are what distinguish an enforced allowlist from an audit-only list.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no software-allowlisting attestation collected
- attestation kind is <value>, expected "software_allowlisting"
- software-allowlisting attestation signature did not verify
- attestation does not document an allowlisting method/technology
- attestation names no enforcement points where allowlisting is applied (e.g. endpoints, servers, CI runners)
- attestation does not document an exception process for authorizing new software
- attestation records no last_reviewed_at date

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.PS-05
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["PR.PS-05"]
  nist_800_53: ["CM-7"]
  iso27001: ["A.8.19"]
  soc2: ["CC6.8"]
```

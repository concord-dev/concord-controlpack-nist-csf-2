# A secure software development life cycle is integrated

`NIST-CSF-2-PR.PS-06` · framework **nist-csf-2** · severity **high** · Protect

## What this control checks

NIST CSF 2.0 PR.PS-06 requires that a secure software development life
cycle is integrated into software development practices. Concord reads a
signed attestation for the SDLC program and verifies that it enumerates
the security gates enforced in the pipeline (e.g. threat modeling, peer
review, security sign-off), the types of security testing performed (e.g.
SAST, DAST, dependency and secret scanning), confirms developers receive
secure-development training, and records a recent review date.

## Why it matters

Most exploitable defects are introduced during development; bolting on
security afterwards is costly and incomplete. Gated design review, layered
automated testing, and trained developers are the practices auditors and
frameworks (NIST SSDF, SA-15) expect from a secure SDLC.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no secure-SDLC attestation collected
- attestation kind is <value>, expected "secure_sdlc"
- secure-SDLC attestation signature did not verify
- attestation names no security gates in the SDLC (e.g. threat modeling, peer review, security sign-off)
- attestation names no security testing types (e.g. SAST, DAST, dependency/secret scanning)
- attestation does not confirm that developers receive secure-development training
- attestation records no last_reviewed_at date

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.PS-06
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["PR.PS-06"]
  nist_800_53: ["SA-3", "SA-15"]
  iso27001: ["A.8.25"]
  soc2: ["CC8.1"]
```

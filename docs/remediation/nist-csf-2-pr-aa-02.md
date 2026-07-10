# Identities are proofed and bound to credentials based on context

`NIST-CSF-2-PR.AA-02` · framework **nist-csf-2** · severity **high** · Protect

## What this control checks

NIST CSF 2.0 PR.AA-02 requires that identities are proofed and bound to
credentials based on the context of interactions. Concord reads a signed
identity-proofing attestation and verifies that it documents the proofing
process, the identity/authenticator assurance levels it targets, the
method used to bind a proofed identity to its credential, and a recent
review date.

## Why it matters

Weak or undocumented proofing lets an attacker enrol under someone else's
identity, defeating every downstream authentication and authorization
control. Requiring an attested, signed process with declared assurance
levels (e.g. NIST SP 800-63 IAL/AAL) is the floor for trustworthy
identities.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no identity-proofing attestation collected
- attestation kind is <value>, expected "identity_proofing"
- identity-proofing attestation signature did not verify
- attestation does not document an identity-proofing process
- attestation does not declare any identity/authenticator assurance levels
- attestation does not document how identities are bound to credentials
- attestation records no last_reviewed_at date

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.AA-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["PR.AA-02"]
  nist_800_53: ["IA-2", "IA-5"]
  iso27001: ["A.5.16"]
  soc2: ["CC6.1"]
```

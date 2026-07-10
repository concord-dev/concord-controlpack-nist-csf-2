# Identity assertions are protected, conveyed, and verified

`NIST-CSF-2-PR.AA-04` · framework **nist-csf-2** · severity **high** · Protect

## What this control checks

NIST CSF 2.0 PR.AA-04 requires that identity assertions are protected,
conveyed, and verified. Concord reads a signed attestation describing the
organization's federation/SSO posture and verifies that it names the
assertion protocols in use (e.g. SAML 2.0, OIDC), documents how
assertions and tokens are protected (signing, encryption, short lifetime,
audience restriction), states how relying parties verify assertions, and
records a recent review date.

## Why it matters

Federated identity moves trust across security domains; a forged,
replayed, or unverified assertion grants an attacker whatever the relying
party would grant the legitimate subject. Signed/encrypted, short-lived,
audience-bound assertions with explicit verification are the baseline for
safe single sign-on.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no identity-assertions attestation collected
- attestation kind is <value>, expected "identity_assertions"
- identity-assertions attestation signature did not verify
- attestation names no identity-assertion protocols (e.g. SAML 2.0, OIDC)
- attestation does not document how assertions/tokens are protected in transit
- attestation does not document how relying parties verify assertions
- attestation records no last_reviewed_at date

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.AA-04
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["PR.AA-04"]
  nist_800_53: ["IA-5", "AC-3"]
  iso27001: ["A.5.17"]
  soc2: ["CC6.1"]
```

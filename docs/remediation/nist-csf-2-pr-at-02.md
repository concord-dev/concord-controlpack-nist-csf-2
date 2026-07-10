# Individuals in specialized roles are provided awareness and training

`NIST-CSF-2-PR.AT-02` · framework **nist-csf-2** · severity **medium** · Protect

## What this control checks

NIST CSF 2.0 PR.AT-02 requires that individuals in specialized roles are
provided with awareness and training so they possess the knowledge and
skills to perform relevant tasks. Concord reads a signed attestation for
the role-based training program and verifies that it enumerates the
specialized roles covered (e.g. incident responders, secure-code
reviewers, administrators), documents the curriculum, confirms completion
is tracked, was delivered within the last 365 days, and records a recent
review date.

## Why it matters

General awareness training does not equip privileged and specialized
personnel for their specific risks. Role-based training that is current
(delivered at least annually) and whose completion is tracked is what
auditors expect for PR.AT-02, and is a prerequisite for holding those
roles accountable.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no specialized-training attestation collected
- attestation kind is <value>, expected "specialized_training"
- specialized-training attestation signature did not verify
- attestation enumerates no specialized roles requiring role-based training
- attestation does not document a specialized-role training curriculum
- attestation does not confirm that training completion is tracked
- specialized-role training last delivered <value> days ago (max <value>)
- attestation records no last_reviewed_at date

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.AT-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["PR.AT-02"]
  nist_800_53: ["AT-3"]
  iso27001: ["A.6.3"]
  soc2: ["CC1.4"]
```

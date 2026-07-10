# Actions performed during an investigation are recorded

`NIST-CSF-2-RS.AN-06` · framework **nist-csf-2** · severity **high** · Respond

## What this control checks

NIST CSF 2.0 RS.AN-06 requires that the actions performed during an
investigation are recorded, and that the integrity and provenance of
those records are preserved. Concord reads a cosigned attestation that
records how investigation actions are logged, how chain of custody is
maintained, and the tooling that enforces both.

## Why it matters

Investigation records are frequently relied on for legal, regulatory,
and insurance purposes, so their integrity and provenance must be
defensible. Attesting to action logging, a chain-of-custody process,
and the enforcing tooling — reviewed at least annually — demonstrates
that responder actions are captured contemporaneously and cannot be
repudiated or tampered with after the fact.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no investigation-recordkeeping attestation collected
- attestation kind is <value>, expected <value>
- investigation-recordkeeping attestation cosign signature did not verify
- investigation-recordkeeping attestation missing required field: <value>
- investigation-recordkeeping attestation lists zero tools enforcing action logging
- investigation-recordkeeping practice last reviewed <value> — older than <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1w**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.AN-06
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.AN-06"]
  nist_800_53: ["IR-4", "AU-6", "IR-5"]
  iso27001: ["A.5.28"]
  soc2: ["CC7.3"]
```

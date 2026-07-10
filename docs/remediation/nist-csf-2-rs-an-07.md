# Incident data and metadata are collected and their integrity preserved

`NIST-CSF-2-RS.AN-07` · framework **nist-csf-2** · severity **high** · Respond

## What this control checks

NIST CSF 2.0 RS.AN-07 requires that incident data and metadata are
collected, and that their integrity and provenance are preserved.
Concord reads a cosigned attestation that records the collection
process, the integrity controls applied to collected data (for example
cryptographic hashing, write-once storage, or access logging), and the
retention period for that data.

## Why it matters

Evidentiary value depends on being able to prove that collected data
has not been altered since acquisition. Attesting to a defined
collection process, explicit integrity controls, and a retention
period — reviewed at least annually — demonstrates the organization
preserves both the integrity and the provenance of incident data so it
remains admissible and useful for downstream analysis.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-data-integrity attestation collected
- attestation kind is <value>, expected <value>
- incident-data-integrity attestation cosign signature did not verify
- incident-data-integrity attestation missing required field: <value>
- incident-data-integrity attestation lists zero integrity controls protecting collected data
- incident-data-integrity process last reviewed <value> — older than <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1w**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.AN-07
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.AN-07"]
  nist_800_53: ["IR-4", "AU-6", "IR-5"]
  iso27001: ["A.5.28"]
  soc2: ["CC7.3"]
```

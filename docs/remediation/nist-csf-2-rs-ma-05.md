# The criteria for initiating incident recovery are applied

`NIST-CSF-2-RS.MA-05` · framework **nist-csf-2** · severity **high** · Respond

## What this control checks

NIST CSF 2.0 RS.MA-05 requires that defined criteria for starting
recovery from an incident be applied, so recovery begins only once
containment/eradication is confirmed and the right approval is given.
Concord reads a cosigned recovery-initiation attestation that records
the criteria that must be met before recovery starts, the approval
process, how the incident is handed off to the recovery process, and
when these criteria were last reviewed.

## Why it matters

Starting recovery before an incident is contained can reintroduce the
adversary or destroy forensic evidence. Applying explicit initiation
criteria with an approval gate prevents a premature restore. The signed
attestation proves the criteria exist, are owned, and are kept current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no recovery-initiation attestation collected
- attestation kind is <value>, expected "recovery_initiation"
- recovery-initiation attestation cosign signature did not verify
- recovery-initiation attestation missing field: <value>
- recovery-initiation criteria last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.MA-05
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.MA-05"]
  nist_800_53: ["IR-4", "IR-5", "IR-8"]
  iso27001: ["A.5.26", "A.5.29"]
  soc2: ["CC7.4", "CC7.5"]
```

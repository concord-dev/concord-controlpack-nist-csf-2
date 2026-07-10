# Recovery activities and progress are communicated to internal and external stakeholders

`NIST-CSF-2-RC.CO-03` · framework **nist-csf-2** · severity **medium** · Recover

## What this control checks

NIST CSF 2.0 RC.CO-03 requires that recovery activities and their progress
be communicated to designated internal and external stakeholders. Concord
reads a cosigned recovery-communication attestation that records the
documented communication plan, the stakeholder matrix that maps who must be
told what, the cadence for status updates during a recovery, and when the
plan was last reviewed.

## Why it matters

During a disruption, leadership, responders, customers, and regulators all
need a consistent picture of where recovery stands; ad-hoc communication
breeds rumor, duplicated effort, and missed regulatory deadlines. The signed
attestation proves a communication plan and stakeholder matrix exist, are
owned, and are kept current rather than improvised mid-incident.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no recovery-communication attestation collected
- attestation kind is <value>, expected "recovery_communication"
- recovery-communication attestation cosign signature did not verify
- recovery-communication attestation missing field: <value>
- recovery communication plan last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RC.CO-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RC.CO-03"]
  nist_800_53: ["IR-4", "CP-2"]
  iso27001: ["A.5.24", "A.5.26"]
  soc2: ["CC2.2", "CC2.3", "CC7.4"]
```

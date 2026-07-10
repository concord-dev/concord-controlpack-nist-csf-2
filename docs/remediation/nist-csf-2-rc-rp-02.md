# Recovery actions are selected, scoped, prioritized, and performed

`NIST-CSF-2-RC.RP-02` · framework **nist-csf-2** · severity **high** · Recover

## What this control checks

NIST CSF 2.0 RC.RP-02 requires that recovery actions be selected, scoped,
prioritized, and performed during an incident. Concord reads a cosigned
recovery-execution attestation that records the recovery playbooks that
define the available actions, the method used to prioritize which actions
run first, how executed recovery actions are tracked to completion, and when
the process was last reviewed.

## Why it matters

Recovery that is improvised burns the golden hour after an incident on
deciding what to do instead of doing it. Pre-selected, scoped, and
prioritized playbooks with execution tracking turn recovery into a
repeatable procedure and give responders an auditable record of what was
done. The signed attestation proves those playbooks and tracking exist, are
owned, and are kept current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no recovery-execution attestation collected
- attestation kind is <value>, expected "recovery_execution"
- recovery-execution attestation cosign signature did not verify
- recovery-execution attestation missing field: <value>
- recovery playbooks last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RC.RP-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RC.RP-02"]
  nist_800_53: ["CP-10", "CP-4", "IR-4"]
  iso27001: ["A.5.29", "A.5.30"]
  soc2: ["A1.2", "A1.3", "CC7.5"]
```

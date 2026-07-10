# Critical mission functions and cybersecurity risk management are considered during recovery

`NIST-CSF-2-RC.RP-04` · framework **nist-csf-2** · severity **medium** · Recover

## What this control checks

NIST CSF 2.0 RC.RP-04 requires that critical mission functions and
cybersecurity risk management be considered when establishing post-incident
operational norms. Concord reads a cosigned recovery-prioritization
attestation that records the critical business functions, the order in which
services are recovered, the dependency mapping that informs that order, and
when the analysis was last reviewed.

## Why it matters

Not everything can be recovered first, and recovering systems in the wrong
order can prolong the outage of the functions that matter most or bring back
still-compromised assets. Explicitly ranking critical functions and mapping
their dependencies ensures recovery effort is spent where it protects the
mission. The signed attestation proves this prioritization exists, is owned,
and is kept current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no recovery-prioritization attestation collected
- attestation kind is <value>, expected "recovery_prioritization"
- recovery-prioritization attestation cosign signature did not verify
- recovery-prioritization attestation missing field: <value>
- recovery prioritization last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RC.RP-04
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RC.RP-04"]
  nist_800_53: ["CP-10", "CP-2", "CP-4"]
  iso27001: ["A.5.29", "A.5.30"]
  soc2: ["A1.2", "CC9.1"]
```

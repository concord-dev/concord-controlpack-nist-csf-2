# End of incident recovery is declared based on documented criteria

`NIST-CSF-2-RC.RP-06` · framework **nist-csf-2** · severity **medium** · Recover

## What this control checks

NIST CSF 2.0 RC.RP-06 requires that the end of incident recovery be declared
based on criteria and that incident-related documentation be completed.
Concord reads a cosigned recovery-completion attestation that records the
completion criteria that must be met to declare recovery over, the authority
empowered to make that declaration, the post-incident review that must be
performed, and when the process was last reviewed.

## Why it matters

Declaring an incident "over" prematurely stands responders down while risk
remains, while never formally closing it leaves the organization in a
perpetual crisis posture and skips the lessons-learned step. Explicit
completion criteria, a named decision authority, and a required
post-incident review make closure a defensible, documented decision. The
signed attestation proves this closure process exists, is owned, and is kept
current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no recovery-completion attestation collected
- attestation kind is <value>, expected "recovery_completion"
- recovery-completion attestation cosign signature did not verify
- recovery-completion attestation missing field: <value>
- recovery completion criteria last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RC.RP-06
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RC.RP-06"]
  nist_800_53: ["CP-10", "IR-4"]
  iso27001: ["A.5.27", "A.5.29"]
  soc2: ["CC7.5"]
```

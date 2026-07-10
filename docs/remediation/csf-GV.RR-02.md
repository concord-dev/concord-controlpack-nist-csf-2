# Cybersecurity roles, responsibilities, and authorities are documented and assigned

`NIST-CSF-2-GV.RR-02` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.RR-02 requires cyber roles, responsibilities, and
authorities to be established and communicated. Concord reads a
cosigned RACI attestation listing the cybersecurity functions and
their accountable owners.

## Why it matters

GV.RR-02 audits hinge on whether named individuals (not "the
security team") own each function. The RACI YAML check enforces
this.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no RACI attestation collected
- RACI attestation cosign signature did not verify
- RACI is missing function <value>
- function <value> has no accountable owner assigned

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1w**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.RR-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["GV.RR-02"]
  iso27001: ["A.5.2"]
  soc2: ["CC1.3"]
```

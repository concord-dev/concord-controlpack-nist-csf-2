# Internal and external stakeholders are understood and prioritized

`NIST-CSF-2-GV.OC-02` · framework **nist-csf-2** · severity **medium** · Govern

## What this control checks

NIST CSF 2.0 GV.OC-02 requires that internal and external
stakeholders are understood, and that their needs and expectations
regarding cybersecurity risk management are understood and
prioritized. Concord reads a cosigned organizational-context
attestation that enumerates the internal and external stakeholders
and records the basis on which they are prioritized.

## Why it matters

Stakeholder identification anchors the rest of the Govern function:
risk appetite, policy, and role assignments are only defensible when
the organization can name who its decisions affect and answer to.
Auditors treat an empty or stale stakeholder register as evidence
that governance is being performed on paper only.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no organizational-context attestation collected
- attestation kind is <value>, expected "organizational_context"
- organizational-context attestation missing field: <value>
- no internal stakeholders identified
- no external stakeholders identified
- organizational-context attestation cosign signature did not verify
- stakeholder context not reviewed within <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.OC-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.OC-02"
  nist_800_53:
  - "PM-11"
  - "RA-9"
  iso27001:
  - "4.2"
  soc2:
  - "CC3.1"
```

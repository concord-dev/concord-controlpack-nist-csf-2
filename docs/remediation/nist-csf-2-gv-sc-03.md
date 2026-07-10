# Cybersecurity supply chain risk management is integrated into the cybersecurity program

`NIST-CSF-2-GV.SC-03` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.SC-03 requires cybersecurity supply chain risk
management to be integrated into the broader cybersecurity and
enterprise risk management programs, including monitoring over the
relationship lifecycle. Concord reads a cosigned C-SCRM integration
attestation that records how supplier risk feeds the enterprise risk
process, the criteria used to assess supplier risk, the ongoing
monitoring approach, and the date the integration was last reviewed.

## Why it matters

Supply-chain risk that is tracked in a silo never reaches the
decision-makers who accept or mitigate it. GV.SC-03 confirms that
supplier risk is folded into the same register and reviews as every
other cyber risk. The attestation records the integration points,
risk criteria, and monitoring so the linkage is auditable and current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no C-SCRM integration attestation collected
- attestation kind is <value>, expected <value>
- C-SCRM integration attestation missing required field: <value>
- C-SCRM integration attestation defines zero supplier risk criteria
- C-SCRM integration attestation cosign signature did not verify
- C-SCRM integration has not been reviewed in the last 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.SC-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.SC-03"
  nist_800_53:
  - "SR-1"
  - "SR-2"
  - "PM-30"
  iso27001:
  - "A.5.19"
  - "A.5.21"
  soc2:
  - "CC9.2"
```

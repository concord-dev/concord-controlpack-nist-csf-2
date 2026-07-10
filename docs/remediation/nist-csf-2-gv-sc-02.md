# Cybersecurity roles and responsibilities for suppliers are established

`NIST-CSF-2-GV.SC-02` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.SC-02 requires cybersecurity roles and
responsibilities for suppliers, customers, and partners to be
established, communicated, and coordinated internally and externally.
Concord reads a cosigned supplier-roles attestation that records the
security responsibilities placed on suppliers, the internal owners
accountable for each supplier tier, the escalation path when
obligations are unmet, and the date the assignments were last reviewed.

## Why it matters

Unowned supplier relationships are where third-party risk hides. GV.SC-02
confirms that both sides know their security obligations and that a named
internal owner and escalation path exist. The attestation makes those
responsibilities and owners explicit so accountability does not fall
through the cracks between teams.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no supplier-roles attestation collected
- attestation kind is <value>, expected <value>
- supplier-roles attestation missing required field: <value>
- supplier-roles attestation defines zero supplier responsibilities
- supplier-roles attestation assigns no internal owners
- supplier-roles attestation cosign signature did not verify
- supplier roles and responsibilities have not been reviewed in the last 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.SC-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.SC-02"
  nist_800_53:
  - "SR-2"
  - "SR-3"
  iso27001:
  - "A.5.19"
  - "A.5.20"
  soc2:
  - "CC9.2"
```

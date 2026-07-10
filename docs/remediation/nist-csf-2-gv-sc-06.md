# Planning and due diligence are performed to reduce supply chain risk before entering formal supplier relationships

`NIST-CSF-2-GV.SC-06` · framework **nist-csf-2** · severity **medium** · Govern

## What this control checks

NIST CSF 2.0 GV.SC-06 requires planning and due diligence to be
performed to reduce cybersecurity risks before entering into formal
supplier or third-party relationships. Concord reads a cosigned
procurement-planning attestation that records the pre-procurement due
diligence process, the risk assessment performed before engagement,
the approval gate that must be cleared before a contract is signed,
and the date the planning process was last reviewed.

## Why it matters

The cheapest time to reduce supplier risk is before the contract is
signed. GV.SC-06 confirms that due diligence and a risk assessment
happen ahead of procurement, gated by an explicit approval, rather
than after a vendor is already embedded. The attestation records the
process and approval gate so pre-procurement rigor is auditable.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no procurement-planning attestation collected
- attestation kind is <value>, expected <value>
- procurement-planning attestation missing required field: <value>
- procurement-planning attestation cosign signature did not verify
- procurement-planning process has not been reviewed in the last 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.SC-06
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.SC-06"
  nist_800_53:
  - "SR-5"
  - "SR-6"
  - "SA-4"
  iso27001:
  - "A.5.19"
  - "A.5.21"
  soc2:
  - "CC9.2"
```

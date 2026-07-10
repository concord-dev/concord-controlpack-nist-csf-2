# Requirements to address cybersecurity risks in supply chains are established

`NIST-CSF-2-GV.SC-05` · framework **nist-csf-2** · severity **high** · Govern

## What this control checks

NIST CSF 2.0 GV.SC-05 requires requirements to address cybersecurity
risks in supply chains to be established, prioritized, and integrated
into contracts and other agreements with suppliers and third parties.
Concord reads a cosigned supply-chain-requirements attestation that
records the contractual requirements imposed on suppliers, the
security clauses embedded in agreements, the method used to verify
those clauses, and the date the requirements were last reviewed.

## Why it matters

Security expectations that never make it into a contract are
unenforceable. GV.SC-05 confirms that requirements such as breach
notification, right-to-audit, and data-protection clauses are written
into supplier agreements and verified. The attestation records the
requirements, clauses, and verification method so auditors can trace
the paper trail from policy to signed contract.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no supply-chain-requirements attestation collected
- attestation kind is <value>, expected <value>
- supply-chain-requirements attestation missing required field: <value>
- supply-chain-requirements attestation defines zero contractual requirements
- supply-chain-requirements attestation defines zero security clauses
- supply-chain-requirements attestation cosign signature did not verify
- supply-chain requirements have not been reviewed in the last 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-GV.SC-05
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "GV.SC-05"
  nist_800_53:
  - "SR-3"
  - "SR-5"
  - "SA-4"
  iso27001:
  - "A.5.20"
  - "A.5.23"
  soc2:
  - "CC9.2"
```

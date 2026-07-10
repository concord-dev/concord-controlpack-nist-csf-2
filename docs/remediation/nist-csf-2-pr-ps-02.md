# Software is maintained, replaced, and removed commensurate with risk

`NIST-CSF-2-PR.PS-02` · framework **nist-csf-2** · severity **high** · Protect

## What this control checks

NIST CSF 2.0 subcategory PR.PS-02 (Platform Security) requires that software
be maintained, replaced, and removed commensurate with risk — in practice,
that security-relevant flaws are remediated within a risk-based window.
Concord verifies this technically by reading AWS Systems Manager (SSM) Patch
Manager compliance: every managed instance in scope must report a COMPLIANT
patch state, and no instance may carry a missing critical or security patch
older than 30 days. This implements NIST 800-53 SI-2 (Flaw Remediation) as
the control behind PR.PS-02. An absent evidence payload denies (fail-closed).

## Why it matters

Unpatched, publicly known vulnerabilities are among the most common root
causes of breaches, because working exploits circulate soon after
disclosure. Enforcing a 30-day ceiling on missing critical and security
patches, measured directly from SSM Patch Manager rather than a self-attested
spreadsheet, closes the window in which an attacker can weaponize a known
flaw. Evaluating each instance individually means a single unpatched host
fails the control rather than being averaged away by a healthy fleet, and
the fail-closed default treats an instance with no reported patch state, or
missing evidence entirely, as non-compliant.

## Evidence

Collected from the `aws` source (`ssm_patch_compliance` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- NIST CSF 2.0 PR.PS-02: no SSM patch-compliance evidence collected
- NIST CSF 2.0 PR.PS-02: instance <value> reports patch-compliance status <value> (expected COMPLIANT) (NIST 800-53 SI-2)
- NIST CSF 2.0 PR.PS-02: instance <value> has a missing critical/security patch <value> days old, exceeding the <value>-day SLA (NIST 800-53 SI-2)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.PS-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "PR.PS-02"
  nist_800_53:
  - "SI-2"
  - "SI-2(2)"
  - "RA-5"
  soc2:
  - "CC7.1"
  pci_dss:
  - "6.3.3"
```

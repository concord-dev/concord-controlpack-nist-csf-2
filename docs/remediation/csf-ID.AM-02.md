# Software inventory (SBOM + dependencies) is maintained per service

`NIST-CSF-2-ID.AM-02` · framework **nist-csf-2** · severity **high** · Identify

## What this control checks

NIST CSF 2.0 ID.AM-02 requires inventories of software platforms
and applications. Concord reads the Snyk org-projects export and
verifies every active project has an SBOM and has been scanned in
the last 30 days.

## Why it matters

Without an SBOM, vuln-management findings cannot be tied back to
specific deployable artefacts.

## Evidence

Collected from the `snyk` source (`org_projects` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no software-inventory evidence collected
- project <value> has no SBOM
- project <value> has not been scanned in <value> days (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.AM-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["ID.AM-02"]
  iso27001: ["A.5.9"]
```

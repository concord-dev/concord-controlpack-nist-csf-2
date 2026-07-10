# Users, services, and hardware are authenticated

`NIST-CSF-2-PR.AA-03` · framework **nist-csf-2** · severity **critical** · Protect

## What this control checks

NIST CSF 2.0 PR.AA-03 requires that users, services, and hardware are
authenticated before access is granted. For interactive AWS access this
means multi-factor authentication on every IAM principal that can sign in
with a password. Concord reads the IAM credential report and fails any
console-enabled, non-root user that has no active MFA device. Absence of a
credential report is treated as a failure (fail-closed).

## Why it matters

Single-factor console access is the most common initial-access vector in
cloud breaches. Enforcing an MFA device on every interactive identity is
the highest-leverage authentication control and a prerequisite for
trustworthy access logging and authorization decisions.

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected — cannot verify MFA on console users
- IAM user <value> has console access without an active MFA device
- root account has console access without MFA — enable a hardware MFA device on root

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.AA-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["PR.AA-03"]
  nist_800_53: ["IA-2", "IA-5"]
  soc2: ["CC6.1"]
  cis_aws: ["1.10"]
```

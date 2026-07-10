# Backups are maintained, protected, and tested

`NIST-CSF-2-PR.DS-12` · framework **nist-csf-2** · severity **high** · Protect

## What this control checks

NIST CSF 2.0 subcategory PR.DS-12 (Data Security) requires that backups of
data be created, maintained, protected against tampering, and tested for
reliability. Concord verifies this technically against the live AWS backup
posture for every in-scope data store (tagged sensitive="true"): RDS
instances must retain automated backups for at least 30 days; DynamoDB
tables must have point-in-time recovery enabled; AWS Backup vaults that
hold in-scope data must be vault-locked so retained recovery points cannot
be deleted or shortened; and each such vault must have had a successful
restore test within the last 365 days. This implements NIST 800-53 CP-9
(System Backup) and CP-9(1) (Testing for Reliability and Integrity) as the
controls behind PR.DS-12. An absent evidence payload denies (fail-closed).

## Why it matters

Backups are the last line of defense against ransomware, accidental
deletion, and silent corruption, but only when they are automated, retained
long enough to outlast a slow-burn compromise, protected from tampering, and
proven restorable. Ransomware operators routinely delete or encrypt backups
first, which is why vault locking (immutable retention) is required rather
than optional, and why an untested backup is treated as a hypothesis rather
than a recovery capability. Reading retention periods, PITR state, vault
locks, and restore-test recency directly from AWS makes the control
continuously verifiable instead of a point-in-time attestation, and each
resource is judged individually so one unprotected store fails the control.

## Evidence

Collected from the `aws` source (`backup_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- NIST CSF 2.0 PR.DS-12: no backup evidence collected
- NIST CSF 2.0 PR.DS-12: in-scope RDS instance <value> has backup retention <value> days (floor is <value>) (NIST 800-53 CP-9)
- NIST CSF 2.0 PR.DS-12: in-scope DynamoDB table <value> has point-in-time recovery disabled (NIST 800-53 CP-9)
- NIST CSF 2.0 PR.DS-12: backup vault <value> holds in-scope data but is not vault-locked (tamper-resistant retention required) (NIST 800-53 CP-9)
- NIST CSF 2.0 PR.DS-12: backup vault <value> has not had a successful restore test in the last <value> days (restore_test_age_days=<value>) (NIST 800-53 CP-9(1))

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **4h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.DS-12
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "PR.DS-12"
  nist_800_53:
  - "CP-9"
  - "CP-9(1)"
  soc2:
  - "A1.2"
  iso27001:
  - "A.8.13"
  hipaa:
  - "164.308(a)(7)(ii)(A)"
```

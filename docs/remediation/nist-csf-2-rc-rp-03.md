# Integrity of backups and other restoration assets is verified before use

`NIST-CSF-2-RC.RP-03` · framework **nist-csf-2** · severity **high** · Recover

## What this control checks

NIST CSF 2.0 RC.RP-03 requires that the integrity of backups and other
restoration assets be verified before they are relied upon for recovery.
Concord reads the AWS backup posture and confirms that every recovery point
has had its integrity verified, that its most recent integrity check
succeeded, and that the check is recent (within 30 days), so a corrupted or
tampered backup is caught before it is ever restored.

## Why it matters

A backup that has never been integrity-checked is a hope, not a recovery
capability. Silent bit-rot, truncated snapshots, and ransomware that quietly
corrupts or encrypts backups before detonating all defeat recovery at the
worst possible moment. Verifying integrity continuously and failing closed
when a check is stale or has failed turns "we have backups" into "we have
restorable backups."

## Evidence

Collected from the `aws` source (`backup_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no backup-integrity evidence collected
- no backup recovery points on record
- backup recovery point <value> has not had its integrity verified
- backup recovery point <value> failed its last integrity check (status=<value>)
- backup recovery point <value> was last integrity-checked <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RC.RP-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RC.RP-03"]
  nist_800_53: ["CP-9(1)", "CP-10", "SI-7"]
  iso27001: ["A.8.13"]
  soc2: ["A1.2", "A1.3"]
```

# Data-at-rest is protected

`NIST-CSF-2-PR.DS-10` · framework **nist-csf-2** · severity **critical** · Protect

## What this control checks

NIST CSF 2.0 subcategory PR.DS-10 (Data Security) requires that the
confidentiality, integrity, and availability of data-at-rest be protected.
The AWS-side technical minimum is that every in-scope data store holding
sensitive information is encrypted at rest with a managed key. Concord reads
the encryption posture of S3 buckets, RDS instances, and EBS volumes tagged
sensitive="true" and denies any such resource whose at-rest encryption is
not configured. This implements NIST 800-53 SC-28 (Protection of
Information at Rest) as the concrete control behind PR.DS-10. An absent
evidence payload denies (fail-closed).

## Why it matters

Encryption at rest is the last line of defense when a storage medium,
snapshot, or backup is exposed through misconfiguration, a stolen
credential, or physical media loss. A single unencrypted bucket, database,
or volume holding sensitive data undermines the entire protection claim, so
each resource is evaluated individually rather than averaged across a mostly
healthy fleet. Requiring KMS-backed encryption — verified continuously from
the live AWS posture rather than asserted once — ensures the ciphertext is
useless without access to the key, and the fail-closed default treats
missing evidence as non-compliant instead of assuming coverage.

## Evidence

Collected from the `aws` source (`storage_encryption` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- NIST CSF 2.0 PR.DS-10: no data-at-rest encryption evidence collected
- NIST CSF 2.0 PR.DS-10: sensitive S3 bucket <value> has no encryption-at-rest configured (NIST 800-53 SC-28)
- NIST CSF 2.0 PR.DS-10: sensitive RDS instance <value> has no encryption-at-rest (NIST 800-53 SC-28)
- NIST CSF 2.0 PR.DS-10: sensitive EBS volume <value> has no encryption-at-rest (NIST 800-53 SC-28)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.DS-10
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "PR.DS-10"
  nist_800_53:
  - "SC-28"
  - "SC-28(1)"
  soc2:
  - "CC6.7"
  iso27001:
  - "A.8.24"
  hipaa:
  - "164.312(a)(2)(iv)"
```

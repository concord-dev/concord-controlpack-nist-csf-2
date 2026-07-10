# Computing hardware and software are monitored to find adverse events

`NIST-CSF-2-DE.CM-09` · framework **nist-csf-2** · severity **high** · Detect

## What this control checks

NIST CSF 2.0 DE.CM-09 requires that computing hardware and software,
runtime environments, and their utilization are monitored to find
potentially adverse events. Concord verifies that in every active AWS
region GuardDuty has an enabled detector (runtime threat monitoring over
VPC, DNS, and CloudTrail telemetry) and AWS Config has a configuration
recorder that is recording (hardware and software configuration
monitoring). Each active region without coverage is reported separately.

## Why it matters

Monitoring of the compute estate only provides assurance if it spans every
region actually in use: GuardDuty and Config are regional services, so a
single region with a suspended detector or a stopped Config recorder is a
blind spot where runtime compromise or unauthorized configuration drift goes
unseen. Concord confirms coverage region by region against the set of active
regions and fails closed when no evidence is collected or no active region
is reported, because absence of monitoring must never read as compliance.

## Evidence

Collected from the `aws` source (`guardduty_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- DE.CM-09: no hardware/software monitoring evidence collected
- DE.CM-09: no active regions reported; monitoring coverage cannot be verified — failing closed
- DE.CM-09: GuardDuty runtime monitoring is not enabled in active region <value>
- DE.CM-09: AWS Config is not recording hardware/software configuration in active region <value>

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-DE.CM-09
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "DE.CM-09"
  nist_800_53:
  - "SI-4"
  - "CA-7"
  - "RA-5"
  iso27001:
  - "A.8.16"
  soc2:
  - "CC7.1"
  - "CC7.2"
```

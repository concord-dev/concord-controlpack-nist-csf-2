# Personnel activity and technology usage are monitored to find adverse events

`NIST-CSF-2-DE.CM-03` · framework **nist-csf-2** · severity **high** · Detect

## What this control checks

NIST CSF 2.0 DE.CM-03 requires that personnel activity and technology usage
are monitored to find potentially adverse events. Concord verifies that AWS
CloudTrail records personnel (user) activity across every region via a
multi-region trail, and that the trail logs management (control-plane)
events for both read and write actions plus at least one data-event
selector, so that both privileged user actions and data-plane technology
usage are captured.

## Why it matters

Insider misuse and account compromise are visible only if the actions of
people and services are logged comprehensively. A trail that covers a single
region leaves activity in every other region invisible; one that logs write
but not read actions misses reconnaissance and data browsing; and one with
no data-event selector never sees object-level access to stored information.
Because a partial log cannot support after-the-fact accountability, Concord
fails closed when no evidence is collected and denies each missing category
independently.

## Evidence

Collected from the `aws` source (`cloudtrail_trails` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- DE.CM-03: no CloudTrail evidence collected
- DE.CM-03: no multi-region CloudTrail trail is logging; personnel activity is not monitored across all regions
- DE.CM-03: CloudTrail is not logging management read events; privileged personnel read activity is not captured
- DE.CM-03: CloudTrail is not logging management write events; personnel change activity is not captured
- DE.CM-03: CloudTrail has no data-event selector; technology usage (data-plane access) is not captured

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-DE.CM-03
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "DE.CM-03"
  nist_800_53:
  - "SI-4"
  - "CA-7"
  - "AU-6"
  iso27001:
  - "A.8.16"
  soc2:
  - "CC7.2"
```

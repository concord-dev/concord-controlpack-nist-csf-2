# Log records are generated and made available for continuous monitoring

`NIST-CSF-2-PR.PS-04` · framework **nist-csf-2** · severity **high** · Protect

## What this control checks

NIST CSF 2.0 subcategory PR.PS-04 (Platform Security) requires that log
records be generated and made available for continuous monitoring. The
AWS-side technical minimum is a CloudTrail configuration that generates
audit records account-wide and covers the required event categories.
Concord denies unless: at least one multi-region CloudTrail trail is both
enabled and actively logging (so every region generates records), and the
trail's event selectors capture management (control-plane) events for both
read and write activity (so privileged read and change activity are both
recorded). This implements NIST 800-53 AU-2 (Event Logging) and AU-12
(Audit Record Generation) as the controls behind PR.PS-04. An absent
evidence payload denies (fail-closed).

## Why it matters

Continuous monitoring, detection, and incident response are only as good as
the logs they read; gaps in log generation are silent and permanent, because
an event that was never recorded cannot be reconstructed later. A
single-region trail leaves every other region dark, a stopped trail records
nothing, and a trail that logs write events but not read events hides
reconnaissance and data-access activity from reviewers. Requiring a
multi-region, actively-logging trail with both read and write management
events establishes the account-wide, always-on generation capability that
every downstream detection and audit control depends on, and the check fails
closed when evidence is missing or any required category is absent.

## Evidence

Collected from the `aws` source (`cloudtrail_event_selectors` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- NIST CSF 2.0 PR.PS-04: no CloudTrail evidence collected
- NIST CSF 2.0 PR.PS-04: no multi-region CloudTrail trail is both enabled and logging; log records are not generated across every region (NIST 800-53 AU-12)
- NIST CSF 2.0 PR.PS-04: CloudTrail is not logging management (control-plane) read events; privileged read activity is not captured for monitoring (NIST 800-53 AU-2)
- NIST CSF 2.0 PR.PS-04: CloudTrail is not logging management (control-plane) write events; privileged change activity is not captured for monitoring (NIST 800-53 AU-2)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.PS-04
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "PR.PS-04"
  nist_800_53:
  - "AU-2"
  - "AU-12"
  - "AU-3"
  soc2:
  - "CC7.2"
  pci_dss:
  - "10.2.1"
```

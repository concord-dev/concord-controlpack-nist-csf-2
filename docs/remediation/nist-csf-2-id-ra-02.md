# Cyber threat intelligence is received from information sharing forums

`NIST-CSF-2-ID.RA-02` · framework **nist-csf-2** · severity **medium** · Identify

## What this control checks

NIST CSF 2.0 ID.RA-02 requires cyber threat intelligence to be received
from information sharing forums and sources. Concord verifies a signed
threat-intel attestation that enumerates the intelligence sources
subscribed to, describes how feeds are ingested and triaged, names the
internal teams that consume the intelligence, and shows the source list
was reviewed within the last year.

## Why it matters

Risk assessment is only as current as the threat intelligence feeding
it. ID.RA-02 fails when there are no named intelligence sources or no
ingestion process, because the organization then relies on discovering
threats after they have already caused an incident rather than from
shared early warning.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no threat-intelligence-sources attestation collected
- attestation kind is <value>, expected "threat_intel_sources"
- threat-intelligence sources missing required field: <value>
- threat-intelligence-sources attestation cosign signature did not verify
- threat-intelligence program subscribes to zero sources
- threat intelligence is routed to zero consuming teams
- threat-intelligence sources have not been reviewed in over <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-ID.RA-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "ID.RA-02"
  nist_800_53:
  - "PM-16"
  - "RA-3"
  iso27001:
  - "A.5.7"
```

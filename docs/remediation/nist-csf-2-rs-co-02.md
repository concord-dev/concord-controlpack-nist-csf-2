# Internal and external stakeholders are notified of incidents

`NIST-CSF-2-RS.CO-02` · framework **nist-csf-2** · severity **high** · Respond

## What this control checks

NIST CSF 2.0 RS.CO-02 requires that internal and external stakeholders
are notified of incidents. Concord reads a cosigned attestation that
records the notification matrix (who is notified for which incident
category and severity), the notification timeframes, and the roster of
internal and external contacts including regulators, customers, and law
enforcement where applicable.

## Why it matters

Late or missed notifications create regulatory exposure (breach-
notification deadlines), erode customer trust, and delay coordinated
response. Attesting to a notification matrix, committed timeframes, and
a maintained contact roster — reviewed at least annually — demonstrates
the organization can reach the right stakeholders quickly when an
incident occurs.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-notification attestation collected
- attestation kind is <value>, expected <value>
- incident-notification attestation cosign signature did not verify
- incident-notification attestation missing required field: <value>
- incident-notification attestation lists zero internal or external contacts
- incident-notification matrix last reviewed <value> — older than <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1w**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.CO-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.CO-02"]
  nist_800_53: ["IR-6", "IR-4"]
  iso27001: ["A.5.5", "A.6.8"]
  soc2: ["CC7.4", "CC2.3"]
```

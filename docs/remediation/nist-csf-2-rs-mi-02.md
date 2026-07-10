# Incidents are eradicated

`NIST-CSF-2-RS.MI-02` · framework **nist-csf-2** · severity **high** · Respond

## What this control checks

NIST CSF 2.0 RS.MI-02 requires that incidents be eradicated - the
adversary's access, malware, and other artifacts removed - before
recovery begins. Concord reads a cosigned incident-eradication
attestation that records the eradication procedures, the method used
to verify the threat is gone, the root-cause analysis process, and
when the procedures were last reviewed.

## Why it matters

Recovery on top of an un-eradicated threat simply hands the adversary
a fresh environment. Documented eradication and verification, backed by
root-cause analysis, ensure the threat is actually removed. The signed
attestation proves the eradication capability exists, is owned, and is
kept current.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-eradication attestation collected
- attestation kind is <value>, expected "incident_eradication"
- incident-eradication attestation cosign signature did not verify
- incident-eradication attestation missing field: <value>
- eradication procedures last reviewed <value> days ago (max <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-RS.MI-02
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf: ["RS.MI-02"]
  nist_800_53: ["IR-4"]
  iso27001: ["A.5.26", "A.5.27"]
  soc2: ["CC7.4", "CC7.5"]
```

# Data-in-transit is protected

`NIST-CSF-2-PR.DS-11` · framework **nist-csf-2** · severity **critical** · Protect

## What this control checks

NIST CSF 2.0 subcategory PR.DS-11 (Data Security) requires that the
confidentiality, integrity, and availability of data-in-transit be
protected. The AWS-side technical minimum is that every endpoint carrying
sensitive data enforces TLS 1.2 or higher. Concord inspects transmission
endpoints tagged sensitive="true" and denies: S3 buckets whose bucket
policy does not deny requests where aws:SecureTransport is false; load
balancer listeners that transmit traffic over a plaintext protocol
(HTTP/TCP); and TLS/HTTPS listeners whose SSL security policy permits
protocol versions below TLS 1.2. This implements NIST 800-53 SC-8
(Transmission Confidentiality and Integrity) as the control behind
PR.DS-11. An absent evidence payload denies (fail-closed).

## Why it matters

Data moving over a network is exposed to interception, tampering, and
downgrade attacks unless it is wrapped in strong, current transport
encryption. Allowing a bucket to serve objects over plain HTTP, or a load
balancer to negotiate TLS 1.0/1.1, leaves a usable path for an attacker on
the network to read or alter sensitive data, so a bucket policy that merely
permits — rather than actively denies — non-TLS access is treated as a
failure. Pinning the minimum to TLS 1.2 rejects protocol versions with known
cryptographic weaknesses. Each endpoint is evaluated on its own and missing
evidence denies, so a single insecure listener cannot hide behind an
otherwise compliant estate.

## Evidence

Collected from the `aws` source (`aws_tls_endpoints` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- NIST CSF 2.0 PR.DS-11: no data-in-transit endpoint evidence collected
- NIST CSF 2.0 PR.DS-11: sensitive S3 bucket <value> does not deny non-TLS requests (missing aws:SecureTransport=false deny) (NIST 800-53 SC-8)
- NIST CSF 2.0 PR.DS-11: sensitive load balancer <value> has a <value> listener on port <value> that transmits data without TLS (NIST 800-53 SC-8)
- NIST CSF 2.0 PR.DS-11: sensitive load balancer <value> listener on port <value> uses SSL policy <value> which permits TLS below 1.2 (NIST 800-53 SC-8)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework nist-csf-2 --control-id NIST-CSF-2-PR.DS-11
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_csf:
  - "PR.DS-11"
  nist_800_53:
  - "SC-8"
  - "SC-8(1)"
  soc2:
  - "CC6.7"
  iso27001:
  - "A.8.24"
  pci_dss:
  - "4.2.1"
  hipaa:
  - "164.312(e)(1)"
```

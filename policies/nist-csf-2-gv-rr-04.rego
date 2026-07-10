package concord.nist_csf_2.gv_rr_04

import rego.v1

# NIST CSF 2.0 GV.RR-04 — cybersecurity is included in human resources
# practices across the personnel lifecycle.

expected_kind := "hr_security_integration"

required_fields := {
    "screening_process",
    "onboarding_security",
    "offboarding_process",
    "last_reviewed_at",
}

deny contains msg if {
    not input.attestation
    msg := "no HR-security-integration attestation collected"
}

deny contains msg if {
    input.attestation.kind != expected_kind
    msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("HR-security-integration attestation missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "HR-security-integration attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    time.now_ns() - reviewed > ((365 * 24) * 60 * 60) * 1000000000
    msg := "HR security integration has not been reviewed in the last 365 days"
}

package concord.nist_csf_2.gv_rr_03

import rego.v1

# NIST CSF 2.0 GV.RR-03 — adequate resources are allocated commensurate
# with the cybersecurity risk strategy.

expected_kind := "resource_allocation"

required_fields := {
    "budget_allocated",
    "staffing_plan",
    "tooling_investment",
    "last_reviewed_at",
}

deny contains msg if {
    not input.attestation
    msg := "no resource-allocation attestation collected"
}

deny contains msg if {
    input.attestation.kind != expected_kind
    msg := sprintf("attestation kind is %q, expected %q", [input.attestation.kind, expected_kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("resource-allocation attestation missing required field: %s", [f])
}

deny contains msg if {
    count(input.attestation.attested_fields.staffing_plan) == 0
    msg := "resource-allocation attestation lists zero staffing commitments"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "resource-allocation attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    time.now_ns() - reviewed > ((365 * 24) * 60 * 60) * 1000000000
    msg := "resource allocation has not been reviewed in the last 365 days"
}

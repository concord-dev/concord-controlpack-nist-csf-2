package concord.nist_csf_2.gv_oc_04

import rego.v1

# NIST CSF 2.0 GV.OC-04 — critical objectives, capabilities, and
# services that external stakeholders depend on or expect from the
# organization are understood and communicated.

required_fields := {"critical_services", "dependencies",
                    "communication_method", "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no critical-services attestation collected"
}

deny contains msg if {
    input.attestation.kind != "critical_services"
    msg := sprintf("attestation kind is %q, expected \"critical_services\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("critical-services attestation missing field: %s", [f])
}

deny contains msg if {
    count(input.attestation.attested_fields.critical_services) == 0
    msg := "no critical services identified"
}

deny contains msg if {
    count(input.attestation.attested_fields.dependencies) == 0
    msg := "no service dependencies identified"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "critical-services attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("critical-services inventory not reviewed within %d days", [max_review_age_days])
}

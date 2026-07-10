package concord.nist_csf_2.gv_oc_05

import rego.v1

# NIST CSF 2.0 GV.OC-05 — outcomes, capabilities, and services that the
# organization depends on are understood and communicated.

required_fields := {"dependent_capabilities", "resilience_requirements",
                    "last_reviewed_at"}

max_review_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no cyber-dependencies attestation collected"
}

deny contains msg if {
    input.attestation.kind != "cyber_dependencies"
    msg := sprintf("attestation kind is %q, expected \"cyber_dependencies\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("cyber-dependencies attestation missing field: %s", [f])
}

deny contains msg if {
    count(input.attestation.attested_fields.dependent_capabilities) == 0
    msg := "no depended-on capabilities or services identified"
}

deny contains msg if {
    count(input.attestation.attested_fields.resilience_requirements) == 0
    msg := "no resilience requirements defined for depended-on services"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "cyber-dependencies attestation cosign signature did not verify"
}

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.attestation.attested_fields.last_reviewed_at)
    age_ns := time.now_ns() - reviewed
    age_ns > max_review_age_days * 24 * 60 * 60 * 1000000000
    msg := sprintf("dependency inventory not reviewed within %d days", [max_review_age_days])
}

package concord.nist_csf_2.rc_rp_04

import rego.v1

max_review_age_days := 365

required_fields := {"critical_functions", "recovery_order",
                    "dependency_mapping", "last_reviewed_at"}

deny contains msg if {
    not input.attestation
    msg := "no recovery-prioritization attestation collected"
}

deny contains msg if {
    input.attestation.kind != "recovery_prioritization"
    msg := sprintf("attestation kind is %q, expected \"recovery_prioritization\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "recovery-prioritization attestation cosign signature did not verify"
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("recovery-prioritization attestation missing field: %s", [f])
}

deny contains msg if {
    input.attestation.attested_fields.review_age_days > max_review_age_days
    msg := sprintf("recovery prioritization last reviewed %d days ago (max %d)", [input.attestation.attested_fields.review_age_days, max_review_age_days])
}

package concord.nist_csf_2.rc_co_03

import rego.v1

max_review_age_days := 365

required_fields := {"communication_plan", "stakeholder_matrix",
                    "update_cadence", "last_reviewed_at"}

deny contains msg if {
    not input.attestation
    msg := "no recovery-communication attestation collected"
}

deny contains msg if {
    input.attestation.kind != "recovery_communication"
    msg := sprintf("attestation kind is %q, expected \"recovery_communication\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "recovery-communication attestation cosign signature did not verify"
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("recovery-communication attestation missing field: %s", [f])
}

deny contains msg if {
    input.attestation.attested_fields.review_age_days > max_review_age_days
    msg := sprintf("recovery communication plan last reviewed %d days ago (max %d)", [input.attestation.attested_fields.review_age_days, max_review_age_days])
}

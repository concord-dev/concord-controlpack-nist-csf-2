package concord.nist_csf_2.rs_ma_05

import rego.v1

max_review_age_days := 365

required_fields := {"initiation_criteria", "approval_process",
                    "handoff_to_recovery", "last_reviewed_at"}

deny contains msg if {
    not input.attestation
    msg := "no recovery-initiation attestation collected"
}

deny contains msg if {
    input.attestation.kind != "recovery_initiation"
    msg := sprintf("attestation kind is %q, expected \"recovery_initiation\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "recovery-initiation attestation cosign signature did not verify"
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("recovery-initiation attestation missing field: %s", [f])
}

deny contains msg if {
    input.attestation.attested_fields.review_age_days > max_review_age_days
    msg := sprintf("recovery-initiation criteria last reviewed %d days ago (max %d)", [input.attestation.attested_fields.review_age_days, max_review_age_days])
}

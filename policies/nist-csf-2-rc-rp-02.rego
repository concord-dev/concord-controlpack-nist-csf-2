package concord.nist_csf_2.rc_rp_02

import rego.v1

max_review_age_days := 365

required_fields := {"recovery_playbooks", "prioritization_method",
                    "execution_tracking", "last_reviewed_at"}

deny contains msg if {
    not input.attestation
    msg := "no recovery-execution attestation collected"
}

deny contains msg if {
    input.attestation.kind != "recovery_execution"
    msg := sprintf("attestation kind is %q, expected \"recovery_execution\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "recovery-execution attestation cosign signature did not verify"
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("recovery-execution attestation missing field: %s", [f])
}

deny contains msg if {
    input.attestation.attested_fields.review_age_days > max_review_age_days
    msg := sprintf("recovery playbooks last reviewed %d days ago (max %d)", [input.attestation.attested_fields.review_age_days, max_review_age_days])
}

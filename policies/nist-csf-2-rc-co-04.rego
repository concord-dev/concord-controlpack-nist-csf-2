package concord.nist_csf_2.rc_co_04

import rego.v1

max_review_age_days := 365

required_fields := {"public_comms_process", "approval_authority",
                    "channels", "last_reviewed_at"}

deny contains msg if {
    not input.attestation
    msg := "no public-recovery-updates attestation collected"
}

deny contains msg if {
    input.attestation.kind != "public_recovery_updates"
    msg := sprintf("attestation kind is %q, expected \"public_recovery_updates\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "public-recovery-updates attestation cosign signature did not verify"
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("public-recovery-updates attestation missing field: %s", [f])
}

deny contains msg if {
    input.attestation.attested_fields.review_age_days > max_review_age_days
    msg := sprintf("public-recovery-updates process last reviewed %d days ago (max %d)", [input.attestation.attested_fields.review_age_days, max_review_age_days])
}

package concord.nist_csf_2.rc_rp_05

import rego.v1

max_review_age_days := 365

required_fields := {"verification_procedure", "acceptance_criteria",
                    "sign_off_role", "last_reviewed_at"}

deny contains msg if {
    not input.attestation
    msg := "no restoration-verification attestation collected"
}

deny contains msg if {
    input.attestation.kind != "restoration_verification"
    msg := sprintf("attestation kind is %q, expected \"restoration_verification\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "restoration-verification attestation cosign signature did not verify"
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("restoration-verification attestation missing field: %s", [f])
}

deny contains msg if {
    input.attestation.attested_fields.review_age_days > max_review_age_days
    msg := sprintf("restoration verification procedure last reviewed %d days ago (max %d)", [input.attestation.attested_fields.review_age_days, max_review_age_days])
}

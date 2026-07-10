package concord.nist_csf_2.rs_ma_03

import rego.v1

max_review_age_days := 365

required_fields := {"category_scheme", "priority_matrix",
                    "assignment_rules", "last_reviewed_at"}

deny contains msg if {
    not input.attestation
    msg := "no incident-categorization attestation collected"
}

deny contains msg if {
    input.attestation.kind != "incident_categorization"
    msg := sprintf("attestation kind is %q, expected \"incident_categorization\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "incident-categorization attestation cosign signature did not verify"
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("incident-categorization attestation missing field: %s", [f])
}

deny contains msg if {
    input.attestation.attested_fields.review_age_days > max_review_age_days
    msg := sprintf("categorization scheme last reviewed %d days ago (max %d)", [input.attestation.attested_fields.review_age_days, max_review_age_days])
}

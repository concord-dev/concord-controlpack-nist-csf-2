package concord.nist_csf_2.rs_mi_02

import rego.v1

max_review_age_days := 365

required_fields := {"eradication_procedures", "verification_method",
                    "root_cause_process", "last_reviewed_at"}

deny contains msg if {
    not input.attestation
    msg := "no incident-eradication attestation collected"
}

deny contains msg if {
    input.attestation.kind != "incident_eradication"
    msg := sprintf("attestation kind is %q, expected \"incident_eradication\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "incident-eradication attestation cosign signature did not verify"
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("incident-eradication attestation missing field: %s", [f])
}

deny contains msg if {
    input.attestation.attested_fields.review_age_days > max_review_age_days
    msg := sprintf("eradication procedures last reviewed %d days ago (max %d)", [input.attestation.attested_fields.review_age_days, max_review_age_days])
}

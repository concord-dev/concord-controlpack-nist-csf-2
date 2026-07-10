package concord.nist_csf_2.rs_ma_02

import rego.v1

max_review_age_days := 365

required_fields := {"triage_process", "validation_criteria",
                    "sla_targets", "last_reviewed_at"}

deny contains msg if {
    not input.attestation
    msg := "no incident-triage attestation collected"
}

deny contains msg if {
    input.attestation.kind != "incident_triage"
    msg := sprintf("attestation kind is %q, expected \"incident_triage\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "incident-triage attestation cosign signature did not verify"
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("incident-triage attestation missing field: %s", [f])
}

deny contains msg if {
    input.attestation.attested_fields.review_age_days > max_review_age_days
    msg := sprintf("triage process last reviewed %d days ago (max %d)", [input.attestation.attested_fields.review_age_days, max_review_age_days])
}

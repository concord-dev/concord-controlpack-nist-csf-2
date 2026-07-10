package concord.nist_csf_2.rs_mi_01

import rego.v1

max_review_age_days := 365

required_fields := {"containment_playbooks", "isolation_procedures",
                    "decision_authority", "last_reviewed_at"}

deny contains msg if {
    not input.attestation
    msg := "no incident-containment attestation collected"
}

deny contains msg if {
    input.attestation.kind != "incident_containment"
    msg := sprintf("attestation kind is %q, expected \"incident_containment\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "incident-containment attestation cosign signature did not verify"
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("incident-containment attestation missing field: %s", [f])
}

deny contains msg if {
    input.attestation.attested_fields.review_age_days > max_review_age_days
    msg := sprintf("containment playbooks last reviewed %d days ago (max %d)", [input.attestation.attested_fields.review_age_days, max_review_age_days])
}
